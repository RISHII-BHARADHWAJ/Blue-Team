<?php
/**
 * ThreatPulse SOAR - Playbook Engine
 *
 * Central orchestrator: loads context, iterates steps, handles branching,
 * manages approval gates with full integrity verification, enforces precise
 * execution cursor tracking, records audit trail, and writes incident timeline.
 *
 * CURSOR TRACKING:
 *   playbook_runs.current_step_order tracks the NEXT step to execute.
 *   On creation: DEFAULT 1 (first step).
 *   Updated atomically whenever the engine advances past a step.
 *   On WAITING_APPROVAL: cursor remains at the paused step's order.
 *   On resume after approval: execution starts at cursor position exactly.
 *   Completed steps are NEVER re-executed (idempotency enforced by PlaybookStepExecutor).
 *
 * APPROVAL RESUME SECURITY:
 *   Before executing an approved action, the engine verifies:
 *   1. Approval is still PENDING and not expired.
 *   2. Approver meets the required_tier minimum.
 *   3. Incident still exists in the database.
 *   4. Playbook run still exists and is in WAITING_APPROVAL state.
 *   5. Payload hash matches current step parameters (tamper detection).
 *   6. Atomically consumes approval (rowCount=1 check prevents double-consume).
 *   7. Resumes at exactly the cursor step.
 *   8. Advances cursor only after the step succeeds.
 *
 * SECURITY GUARANTEES:
 * - Never eval(), exec(), shell_exec(), system(), backtick any data.
 * - All handlers resolved from hard-coded ActionRegistry.
 * - Context loaded exclusively from authoritative DB state.
 * - Step cap of 100 prevents infinite branch loops.
 * - Client-supplied tier/role values are NEVER trusted; server session used.
 */

require_once __DIR__ . '/ActionRegistry.php';
require_once __DIR__ . '/ActionResult.php';
require_once __DIR__ . '/PlaybookContext.php';
require_once __DIR__ . '/PlaybookRepository.php';
require_once __DIR__ . '/PlaybookRunManager.php';
require_once __DIR__ . '/PlaybookStepExecutor.php';
require_once __DIR__ . '/PlaybookValidator.php';
require_once __DIR__ . '/../IncidentRepository.php';
require_once __DIR__ . '/../IncidentTimeline.php';
require_once __DIR__ . '/../IocRepository.php';
require_once __DIR__ . '/../SoarAuth.php';

class PlaybookEngine {

    private const MAX_STEPS_PER_RUN = 100;

    private PlaybookRepository  $repo;
    private PlaybookRunManager  $runManager;
    private PlaybookStepExecutor $executor;
    private IncidentTimeline    $timeline;
    private IocRepository       $iocRepo;
    private IncidentRepository  $incRepo;
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo        = $pdo;
        $this->repo       = new PlaybookRepository($pdo);
        $this->runManager = new PlaybookRunManager($pdo);
        $this->executor   = new PlaybookStepExecutor($pdo);
        $this->timeline   = new IncidentTimeline($pdo);
        $this->iocRepo    = new IocRepository($pdo);
        $this->incRepo    = new IncidentRepository($pdo);
    }

    /**
     * Start a new playbook run.
     *
     * @param int    $playbookId  Playbook to execute
     * @param int    $incidentId  Target incident
     * @param string $mode        MANUAL | AUTOMATIC | DRY_RUN
     * @param array  $actor       Server-side resolved actor ['id' => ..., 'username' => ..., 'tier' => ...]
     * @return array Completed run record
     */
    public function startRun(int $playbookId, int $incidentId, string $mode = 'MANUAL', array $actor = []): array {
        $playbook = $this->repo->findPlaybook($playbookId);
        if (!$playbook || !$playbook['is_active']) {
            throw new InvalidArgumentException("Playbook #{$playbookId} not found or inactive.");
        }

        $incident = $this->incRepo->find($incidentId, true);
        if (!$incident) {
            throw new InvalidArgumentException("Incident #{$incidentId} not found.");
        }

        if (!empty($incident['is_simulated'])) $mode = 'DRY_RUN';

        // Create run record locking to the exact playbook definition version; cursor starts at 1
        $version = (int)($playbook['version'] ?? 1);
        $run     = $this->runManager->createRun($playbookId, $incidentId, $mode, $actor['id'] ?? null, $version);
        $runId   = $run['id'];

        // Concurrency lock: atomic PENDING → RUNNING transition
        if (!$this->runManager->acquireLock($runId)) {
            throw new RuntimeException("Playbook run #{$runId} could not acquire execution lock (already running).");
        }

        // Build immutable context exclusively from authoritative DB state
        $alerts = $this->incRepo->getAttachedAlerts($incidentId);
        $iocs   = $this->iocRepo->getIncidentIocs($incidentId);
        $ctx    = new PlaybookContext($incident, $alerts, $iocs, [], $actor, $run, $mode);

        $this->auditLog($actor['username'] ?? 'system', 'playbook_started', $incident['incident_number'] ?? '', 'success', [
            'playbook_id' => $playbookId, 'run_id' => $runId, 'mode' => $mode,
        ]);
        $this->timeline->addEvent(
            $incidentId, 'PLAYBOOK_STARTED', IncidentTimeline::ACTOR_PLAYBOOK,
            $actor['username'] ?? 'playbook-engine',
            "Playbook '{$playbook['display_name']}' started ({$mode})",
            ['playbook_id' => $playbookId, 'run_id' => $runId, 'mode' => $mode]
        );

        // Execute from step 1 (cursor = 1 by default)
        $this->executeSteps($runId, $playbookId, $incidentId, $ctx, $playbook, 1);

        return $this->repo->findRun($runId) ?? [];
    }

    /**
     * Resume a WAITING_APPROVAL run after a human approval decision.
     *
     * Full security verification sequence (all must pass before execution):
     * 1. Run exists and is WAITING_APPROVAL.
     * 2. Approval exists, is PENDING, has not expired.
     * 3. Approver meets the required_tier for this approval request.
     * 4. Incident still exists in the database.
     * 5. Payload hash matches current step parameters (tamper detection).
     * 6. Atomically consume approval (rowCount=1 guard).
     * 7. Resume at the cursor step — never re-run earlier steps.
     * 8. Cursor advances only after each step completes.
     *
     * @param int    $runId      playbook_runs.id
     * @param int    $approvalId approval_requests.id
     * @param int    $reviewerId users.id of the approving analyst
     * @param string $decision   'APPROVED' or 'REJECTED'
     * @param array  $actor      Server-side resolved actor (tier MUST come from server session)
     * @param string $reviewerTier  Server-side resolved tier (MUST NOT come from client input)
     */
    public function resumeAfterApproval(
        int    $runId,
        int    $approvalId,
        int    $reviewerId,
        string $decision,
        array  $actor = [],
        string $reviewerTier = SoarAuth::TIER_1
    ): array {
        // ---- Check 1: Run exists and is WAITING_APPROVAL -------------------
        $run = $this->repo->findRun($runId);
        if (!$run || $run['status'] !== 'WAITING_APPROVAL') {
            throw new InvalidArgumentException("Run #{$runId} is not awaiting approval.");
        }

        // ---- Check 2: Approval exists, is PENDING, not expired ------------
        $approval = $this->repo->findApprovalById($approvalId);
        if (!$approval) {
            throw new RuntimeException("Approval #{$approvalId} not found.");
        }
        if ($approval['status'] !== 'PENDING') {
            throw new RuntimeException("Approval #{$approvalId} has already been processed (status: {$approval['status']}).");
        }
        if (strtotime($approval['expires_at']) <= time()) {
            throw new RuntimeException("Approval #{$approvalId} has expired.");
        }
        // Also verify it belongs to this run
        if ((int)$approval['playbook_run_id'] !== $runId) {
            throw new RuntimeException("Approval #{$approvalId} does not belong to run #{$runId}.");
        }

        // ---- Check 3: Approver tier meets required_tier --------------------
        $requiredTier = strtoupper($approval['required_tier'] ?? 'LEAD');
        if (!SoarAuth::meetsMinimumTier($reviewerTier, $requiredTier)) {
            throw new RuntimeException(
                "Approver tier '{$reviewerTier}' does not meet required tier '{$requiredTier}' for this approval request."
            );
        }

        // ---- Check 4: Incident still exists --------------------------------
        $incidentId = (int)($run['incident_id'] ?? 0);
        $incident   = $this->incRepo->find($incidentId, true);
        if (!$incident) {
            throw new RuntimeException("Incident #{$incidentId} no longer exists — cannot resume approval.");
        }

        // ---- Check 5: Payload hash integrity check -------------------------
        // Compare stored payload_hash against current step parameters.
        // Rejects approval if the step definition was tampered with after the request was created.
        $cursorStepOrder = (int)($run['current_step_order'] ?? 1);
        $playbookId      = (int)$run['playbook_id'];
        $steps           = $this->repo->getSteps($playbookId);
        $cursorStep      = null;
        foreach ($steps as $s) {
            if ((int)$s['step_order'] === $cursorStepOrder) {
                $cursorStep = $s;
                break;
            }
        }

        if ($cursorStep === null) {
            throw new RuntimeException("Cursor step order {$cursorStepOrder} not found in playbook #{$playbookId}.");
        }

        $currentParams  = $cursorStep['action_parameters'] ?? '[]';
        if (is_array($currentParams)) {
            $currentParams = json_encode($currentParams, JSON_UNESCAPED_SLASHES);
        }
        $currentHash    = hash('sha256', $currentParams);
        $storedHash     = $approval['payload_hash'] ?? null;

        if ($storedHash !== null && !hash_equals($storedHash, $currentHash)) {
            throw new RuntimeException(
                "Approval integrity check failed: step parameters have changed since approval was requested. " .
                "This approval is no longer valid. A new approval request must be created."
            );
        }

        // ---- Check 6: Atomically consume approval --------------------------
        $consumed = $this->repo->consumeApproval($approvalId, $reviewerId, $decision);
        if (!$consumed) {
            // This can happen if two concurrent requests race — only one wins
            throw new RuntimeException("Approval #{$approvalId} could not be consumed (already processed or expired by a concurrent request).");
        }

        // ---- Post-consumption: approved or rejected -------------------------
        if (strtoupper($decision) === 'APPROVED') {
            $this->runManager->transition($runId, 'RUNNING');
            $this->timeline->addEvent(
                $incidentId, 'APPROVAL_GRANTED', IncidentTimeline::ACTOR_ANALYST,
                $actor['username'] ?? 'analyst',
                "Approval granted for run #{$runId} by {$actor['username']} ({$reviewerTier})",
                ['approval_id' => $approvalId, 'reviewer_id' => $reviewerId, 'tier' => $reviewerTier]
            );

            // Re-load context from authoritative DB state
            $alerts  = $this->incRepo->getAttachedAlerts($incidentId);
            $iocs    = $this->iocRepo->getIncidentIocs($incidentId);
            $execCtx = $run['execution_context'] ?? [];
            $mode    = is_array($execCtx) ? ($execCtx['mode'] ?? 'MANUAL') : 'MANUAL';
            $ctx     = new PlaybookContext($incident, $alerts, $iocs, [], $actor, $run, $mode);
            $playbook = $this->repo->findPlaybook($playbookId) ?? [];

            // ---- Check 7: Resume EXACTLY at the cursor step ----------------
            // executeSteps() will skip all steps with order < $cursorStepOrder.
            // PlaybookStepExecutor::executeStep() will also reject re-execution
            // of any step that already has a SUCCESS result (idempotency guard).
            $this->executeSteps($runId, $playbookId, $incidentId, $ctx, $playbook, $cursorStepOrder);

        } else {
            $this->runManager->transition($runId, 'FAILED', 'Approval rejected by analyst.');
            $this->timeline->addEvent(
                $incidentId, 'APPROVAL_REJECTED', IncidentTimeline::ACTOR_ANALYST,
                $actor['username'] ?? 'analyst',
                "Approval rejected for run #{$runId}",
                ['approval_id' => $approvalId]
            );
        }

        return $this->repo->findRun($runId) ?? [];
    }

    // ---- Private step-iteration loop ----------------------------------------

    /**
     * Execute playbook steps starting from $startFromStepOrder.
     * Steps with order < $startFromStepOrder are skipped (already completed).
     * Cursor is advanced in the DB after each step completes.
     *
     * @param int $startFromStepOrder  The NEXT step order to execute (cursor position).
     */
    private function executeSteps(
        int    $runId,
        int    $playbookId,
        int    $incidentId,
        PlaybookContext $ctx,
        array  $playbook,
        int    $startFromStepOrder = 1
    ): void {
        $steps = $this->repo->getSteps($playbookId);
        if (empty($steps)) {
            $this->runManager->transition($runId, 'COMPLETED');
            return;
        }

        // Index steps by id for branch lookups
        $stepById     = array_column($steps, null, 'id');
        $isDryRun     = $ctx->isDryRun();
        $executedCount = 0;

        // Find the starting step by cursor position
        $currentStep = null;
        foreach ($steps as $s) {
            if ((int)$s['step_order'] >= $startFromStepOrder) {
                $currentStep = $s;
                break;
            }
        }

        while ($currentStep !== null && $executedCount < self::MAX_STEPS_PER_RUN) {
            $executedCount++;
            $stepOrder = (int)$currentStep['step_order'];

            // Update cursor to the current step being executed
            $this->repo->updateCursor($runId, $stepOrder);

            $this->timeline->addEvent(
                $incidentId, 'PLAYBOOK_STEP', IncidentTimeline::ACTOR_PLAYBOOK,
                'playbook-engine',
                "Executing step {$stepOrder}: {$currentStep['step_name']} ({$currentStep['action_type']})",
                ['run_id' => $runId, 'step_order' => $stepOrder]
            );

            // Determine retry attempt number from existing results
            $lastResult = $this->repo->findLatestStepResult($runId, $stepOrder);
            $attempt    = $lastResult ? ((int)$lastResult['attempt_number'] + 1) : 1;

            // Retry loop (PlaybookStepExecutor handles idempotency guard internally)
            do {
                $result = $this->executor->executeStep($currentStep, $ctx, $runId, $attempt);
                if ($result->status === ActionResult::STATUS_WAITING_APPROVAL) {
                    break;
                }
                if ($result->isSuccess()) {
                    break;
                }
                $attempt++;
            } while ($this->executor->shouldRetry($currentStep['action_type'], $result, $attempt - 1));

            // Handle approval gate: pause execution, store cursor, create approval request
            if ($result->status === ActionResult::STATUS_WAITING_APPROVAL) {
                // Cursor remains at the current step — not advanced until after approval
                $approvalId = $this->repo->createApprovalRequest([
                    'playbook_run_id'    => $runId,
                    'incident_id'        => $incidentId,
                    'action_name'        => $currentStep['action_type'],
                    'action_description' => $currentStep['step_name'],
                    'action_payload'     => $currentStep['action_parameters'] ?? [],
                    'required_tier'      => $playbook['min_approval_tier'] ?? 'LEAD',
                    'expires_at'         => date('Y-m-d H:i:s', strtotime('+24 hours')),
                ]);
                $this->runManager->transition($runId, 'WAITING_APPROVAL');
                $this->timeline->addEvent(
                    $incidentId, 'APPROVAL_REQUESTED', IncidentTimeline::ACTOR_PLAYBOOK,
                    'playbook-engine',
                    "Approval required for {$currentStep['action_type']} (step {$stepOrder})",
                    ['approval_id' => $approvalId, 'run_id' => $runId, 'step_order' => $stepOrder]
                );
                return;
            }

            // Advance cursor past the completed step
            $nextStep = $this->findNextStep($currentStep, $stepById, $steps, $result);

            if ($nextStep === 'FAILED') {
                $this->runManager->transition($runId, 'FAILED', $result->message, $stepOrder);
                $this->auditLog('system', 'playbook_step_failed', '', 'failure', [
                    'run_id' => $runId, 'step_order' => $stepOrder, 'error' => $result->message,
                ]);
                return;
            }

            // Update cursor to next step order BEFORE advancing loop
            if ($nextStep !== null) {
                $this->repo->updateCursor($runId, (int)$nextStep['step_order']);
            }
            $currentStep = $nextStep;
        }

        // Loop ended
        if ($executedCount >= self::MAX_STEPS_PER_RUN) {
            $this->runManager->transition($runId, 'FAILED', 'Exceeded maximum step execution count (' . self::MAX_STEPS_PER_RUN . ').');
        } else {
            $this->runManager->transition($runId, 'COMPLETED');
            $this->auditLog('system', 'playbook_completed', '', 'success', ['run_id' => $runId, 'dry_run' => $isDryRun]);
        }
    }

    /**
     * Determine the next step to execute based on branching logic.
     * Returns: array (next step), 'FAILED' (terminal failure), or null (run complete).
     *
     * @param array  $currentStep  The just-executed step
     * @param array  $stepById     Steps indexed by id
     * @param array  $stepsOrdered Steps in step_order ASC sequence
     * @param ActionResult $result  Outcome of the step
     * @return array|string|null
     */
    private function findNextStep(array $currentStep, array $stepById, array $stepsOrdered, ActionResult $result): array|string|null {
        if ($result->isSuccess()) {
            $nextStepId = $currentStep['on_success_step'] ?? null;
        } else {
            $nextStepId = $currentStep['on_failure_step'] ?? null;
            if ($nextStepId === null) {
                return 'FAILED';
            }
        }

        if ($nextStepId !== null) {
            return $stepById[(int)$nextStepId] ?? null;
        }

        // Sequential: find next step with higher order
        $currentOrder = (int)$currentStep['step_order'];
        foreach ($stepsOrdered as $s) {
            if ((int)$s['step_order'] > $currentOrder) {
                return $s;
            }
        }
        return null; // No more steps
    }

    private function auditLog(string $actor, string $action, string $target, string $result, array $details): void {
        if (!$this->pdo) return;
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent)
                VALUES (?,?,?,?,?,?,?)
            ");
            $stmt->execute([
                substr($actor, 0, 50), '127.0.0.1',
                substr($action, 0, 100), substr($target, 0, 255), $result,
                substr(json_encode($details, JSON_UNESCAPED_SLASHES), 0, 1000),
                'ThreatPulse-PlaybookEngine/1.0',
            ]);
        } catch (Exception $e) {}
    }
}
