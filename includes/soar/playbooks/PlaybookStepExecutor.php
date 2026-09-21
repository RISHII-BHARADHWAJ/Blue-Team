<?php
/**
 * ThreatPulse SOAR - Playbook Step Executor
 *
 * Executes a single allowlisted playbook step:
 * 1. Idempotency check — return existing SUCCESS without re-executing
 * 2. Validate action_type against the hard-coded ActionRegistry allowlist
 * 3. Resolve {{template}} variables against the immutable PlaybookContext
 * 4. Check approval requirements (flag WAITING_APPROVAL if gated)
 * 5. Execute registered handler via trusted ActionRegistry dispatch
 * 6. Detect (not enforce) timeout via elapsed-time measurement
 * 7. Record step result to playbook_step_results
 * 8. Return ActionResult
 *
 * TIMEOUT SEMANTICS — IMPORTANT:
 *
 *   PHP cannot forcibly terminate an already-executing synchronous function.
 *   What this class provides is TIMEOUT DETECTION, not TIMEOUT ENFORCEMENT.
 *
 *   - Before execution: record $startedAt via microtime(true).
 *   - After execution: compute $elapsed = microtime(true) - $startedAt.
 *   - If $elapsed > timeout_seconds AND the result is not already failed:
 *     the step is marked FAILED with reason "TIMEOUT_DETECTED".
 *   - The action WAS already completed (or partially executed) before detection.
 *   - No PHP process is killed. No SIGKILL is sent.
 *
 *   Future privileged response actions that require real process-level termination
 *   MUST execute through an isolated worker/job architecture, not this synchronous
 *   PHP executor. See docs/soar/playbook-engine.md §Timeout Semantics.
 *
 * SECURITY GUARANTEES:
 * - No eval(), exec(), shell_exec(), system(), backtick, or dynamic include.
 * - All action handlers resolved from hard-coded ActionRegistry.
 * - Context loaded from authoritative DB state via PlaybookContext.
 * - Idempotency guard prevents accidental double-execution on resume.
 */

require_once __DIR__ . '/ActionRegistry.php';
require_once __DIR__ . '/ActionResult.php';
require_once __DIR__ . '/PlaybookContext.php';
require_once __DIR__ . '/PlaybookRepository.php';
require_once __DIR__ . '/TemplateResolver.php';

class PlaybookStepExecutor {

    public const MAX_RETRIES            = 2;
    public const MAX_EXECUTION_STEPS    = 100;   // Loop guard — see PlaybookEngine
    public const RETRYABLE_ACTIONS      = ['ENRICH_IOCS', 'NOTIFY_ANALYST'];
    public const NON_RETRYABLE_STATUSES = ['WAITING_APPROVAL', 'SKIPPED'];

    private ActionRegistry    $registry;
    private TemplateResolver  $resolver;
    private PlaybookRepository $repo;
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo      = $pdo;
        $this->registry = new ActionRegistry($pdo);
        $this->resolver  = new TemplateResolver();
        $this->repo      = new PlaybookRepository($pdo);
    }

    /**
     * Execute one step. Returns ActionResult.
     *
     * @param array           $step    Row from playbook_steps (authoritative DB row)
     * @param PlaybookContext  $ctx     Immutable context snapshot
     * @param int             $runId   playbook_runs.id
     * @param int             $attempt Attempt number (1-based); caller manages retry loop
     */
    public function executeStep(array $step, PlaybookContext $ctx, int $runId, int $attempt = 1): ActionResult {
        $stepOrder  = (int)($step['step_order'] ?? 0);
        $actionType = strtoupper(trim($step['action_type'] ?? ''));
        $timeout    = (int)($step['timeout_seconds'] ?? 60);

        // ---- 0. Idempotency guard -------------------------------------------
        // If this step already has a SUCCESS result for this run, return it
        // immediately without re-executing. Prevents double-execution on resume.
        $existingSuccess = $this->repo->findSuccessfulStepResult($runId, $stepOrder);
        if ($existingSuccess !== null) {
            $output = [];
            if (!empty($existingSuccess['output'])) {
                $output = is_string($existingSuccess['output'])
                    ? (json_decode($existingSuccess['output'], true) ?? [])
                    : $existingSuccess['output'];
            }
            return new ActionResult(
                ActionResult::STATUS_SUCCESS,
                '[IDEMPOTENCY] Step already completed successfully — returning cached result.',
                $output,
                (bool)($existingSuccess['is_dry_run'] ?? false)
            );
        }

        $startedAtWall = date('Y-m-d H:i:s');
        $startedAtMono = microtime(true);

        // ---- 1. Allowlist check ------------------------------------------------
        if (!$this->registry->isAllowed($actionType)) {
            $result = new ActionResult(ActionResult::STATUS_FAILED, "Action '{$actionType}' is not in the registered allowlist.");
            $this->recordStepResult($step, $runId, $result, $startedAtWall, $attempt, $ctx->isDryRun());
            return $result;
        }

        // ---- 2. Resolve templates ----------------------------------------------
        $rawParams = $step['action_parameters'] ?? [];
        if (is_string($rawParams)) {
            $rawParams = json_decode($rawParams, true) ?? [];
        }
        $tplErrors = [];
        $params    = $this->resolveParameters($rawParams, $ctx->toTemplateScope(), $tplErrors);
        if (!empty($tplErrors)) {
            $result = new ActionResult(ActionResult::STATUS_FAILED, 'Template resolution failed: ' . implode('; ', $tplErrors));
            $this->recordStepResult($step, $runId, $result, $startedAtWall, $attempt, $ctx->isDryRun());
            return $result;
        }

        // ---- 3. Approval gate check -------------------------------------------
        $def = $this->registry->getDefinition($actionType);
        if ($def->requiresApproval && !$ctx->isDryRun()) {
            // Signal waiting — actual approval_request creation is done by PlaybookEngine
            $result = new ActionResult(ActionResult::STATUS_WAITING_APPROVAL, "Action {$actionType} requires human approval before execution.");
            $this->recordStepResult($step, $runId, $result, $startedAtWall, $attempt, $ctx->isDryRun());
            return $result;
        }

        // ---- 4. Execute handler -----------------------------------------------
        // TIMEOUT NOTE: We record time BEFORE and AFTER execution.
        // We DETECT timeout after the fact. We CANNOT terminate a running PHP function.
        try {
            $handler = $this->registry->getHandler($actionType);
            $result  = $handler->execute($params, $ctx->toArray(), $ctx->isDryRun());
        } catch (Throwable $e) {
            // Stack traces are never exposed to analyst-facing output
            $result = new ActionResult(ActionResult::STATUS_FAILED, 'Action execution error. Ref: ' . substr($e->getMessage(), 0, 200));
        }

        // ---- 5. Timeout detection (not enforcement) ---------------------------
        $elapsed = microtime(true) - $startedAtMono;
        if ($timeout > 0 && $elapsed > $timeout && !$result->isFailed()) {
            // The action completed but exceeded its configured timeout.
            // Mark as FAILED: the result cannot be trusted for timing-sensitive ops.
            // NOTE: the action side effects may have already occurred.
            $result = new ActionResult(
                ActionResult::STATUS_FAILED,
                sprintf(
                    'TIMEOUT_DETECTED: step execution took %.2fs but timeout is %ds. ' .
                    'Action may have already executed — see step result output for details. ' .
                    'Note: PHP cannot forcibly terminate a running function.',
                    $elapsed,
                    $timeout
                ),
                $result->toArray()
            );
        }

        // ---- 6. Record --------------------------------------------------------
        $this->recordStepResult($step, $runId, $result, $startedAtWall, $attempt, $ctx->isDryRun(), $elapsed);
        return $result;
    }

    /**
     * Determine if a failed step should be retried.
     * Non-retryable statuses and non-retryable action types are never retried.
     * Attempt count is 1-based; MAX_RETRIES is the maximum number of retry attempts
     * (attempts 2 through MAX_RETRIES+1 are retries).
     */
    public function shouldRetry(string $actionType, ActionResult $result, int $attempt): bool {
        if ($attempt > self::MAX_RETRIES) return false;
        if (in_array($result->status, self::NON_RETRYABLE_STATUSES, true)) return false;
        if (!in_array($actionType, self::RETRYABLE_ACTIONS, true)) return false;
        return $result->isFailed();
    }

    // ---- Private helpers ---------------------------------------------------

    private function resolveParameters(array $params, array $scope, array &$errors): array {
        $resolved = [];
        foreach ($params as $key => $value) {
            if (is_string($value)) {
                try {
                    $resolved[$key] = $this->resolver->resolve($value, $scope);
                } catch (RuntimeException $e) {
                    $errors[] = $e->getMessage();
                    $resolved[$key] = '';
                }
            } elseif (is_array($value)) {
                $resolved[$key] = $this->resolveParameters($value, $scope, $errors);
            } else {
                $resolved[$key] = $value;
            }
        }
        return $resolved;
    }

    private function recordStepResult(
        array $step, int $runId, ActionResult $result,
        string $startedAtWall, int $attempt, bool $isDryRun,
        float $elapsed = 0.0
    ): void {
        $status = match ($result->status) {
            ActionResult::STATUS_WAITING_APPROVAL => 'WAITING_APPROVAL',
            ActionResult::STATUS_SUCCESS          => 'SUCCESS',
            ActionResult::STATUS_SKIPPED          => 'SKIPPED',
            default                               => 'FAILED',
        };

        $output = $result->toArray();
        if ($elapsed > 0) {
            $output['_elapsed_seconds'] = round($elapsed, 4);
        }

        $this->repo->logStepResult([
            'playbook_run_id' => $runId,
            'step_id'         => (int)($step['id'] ?? 0),
            'step_order'      => (int)($step['step_order'] ?? 0),
            'action_type'     => strtoupper($step['action_type'] ?? ''),
            'attempt_number'  => $attempt,
            'status'          => $status,
            'started_at'      => $startedAtWall,
            'completed_at'    => date('Y-m-d H:i:s'),
            'output'          => $output,
            'error_message'   => $result->isFailed() ? $result->message : null,
            'is_dry_run'      => $isDryRun,
        ]);
    }
}
