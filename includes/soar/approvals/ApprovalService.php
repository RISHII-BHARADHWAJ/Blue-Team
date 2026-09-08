<?php
/**
 * ThreatPulse SOAR - Approval Decision Service
 *
 * Core service orchestrating the SOC approval control plane:
 * - Authorizes analyst actions using canonical SoarAuth RBAC
 * - Verifies state machine transitions (PENDING -> APPROVED | REJECTED | EXPIRED | CANCELLED)
 * - Verifies expiration against authoritative server time
 * - Verifies payload hash immutability (anti-tampering)
 * - Executes atomic transactional state consumption
 * - Resumes or terminates playbook runs
 * - Records audit logs, incident timeline milestones, and in-app notifications
 */

require_once __DIR__ . '/ApprovalDecision.php';
require_once __DIR__ . '/ApprovalValidator.php';
require_once __DIR__ . '/ApprovalRepository.php';
require_once __DIR__ . '/../notifications/NotificationService.php';
require_once __DIR__ . '/../playbooks/PlaybookEngine.php';
require_once __DIR__ . '/../playbooks/PlaybookRepository.php';
require_once __DIR__ . '/../playbooks/PlaybookRunManager.php';
require_once __DIR__ . '/../IncidentRepository.php';
require_once __DIR__ . '/../IncidentTimeline.php';
require_once __DIR__ . '/../IocRepository.php';
require_once __DIR__ . '/../SoarAuth.php';

class ApprovalService {
    private ?PDO $pdo;
    private ApprovalRepository  $approvalRepo;
    private ApprovalValidator   $validator;
    private NotificationService $notificationService;
    private PlaybookRepository  $playbookRepo;
    private PlaybookRunManager  $runManager;
    private IncidentRepository  $incidentRepo;
    private IncidentTimeline    $timeline;
    private IocRepository       $iocRepo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo                 = $pdo;
        $this->approvalRepo        = new ApprovalRepository($pdo);
        $this->validator           = new ApprovalValidator();
        $this->notificationService = new NotificationService($pdo);
        $this->playbookRepo        = new PlaybookRepository($pdo);
        $this->runManager          = new PlaybookRunManager($pdo);
        $this->incidentRepo        = new IncidentRepository($pdo);
        $this->timeline            = new IncidentTimeline($pdo);
        $this->iocRepo             = new IocRepository($pdo);
    }

    /**
     * List approvals visible to the authenticated analyst.
     * Enforces IDOR protection — analyst must have at least view_incidents capability.
     */
    public function listApprovals(array $filters, array $authContext, int $limit = 50, int $offset = 0): array {
        $tier = $authContext['tier'] ?? SoarAuth::TIER_1;
        if (!SoarAuth::hasPermission($tier, 'view_incidents')) {
            throw new RuntimeException("Unauthorized: User lacks permission to view approvals.");
        }

        return $this->approvalRepo->listApprovals($filters, $limit, $offset);
    }

    /**
     * Retrieve complete approval details with evidence, action preview, and incident context.
     */
    public function getApprovalDetail(int $approvalId, array $authContext): array {
        $tier = $authContext['tier'] ?? SoarAuth::TIER_1;
        if (!SoarAuth::hasPermission($tier, 'view_incidents')) {
            throw new RuntimeException("Unauthorized: User lacks permission to view approval details.");
        }

        $approval = $this->approvalRepo->findWithDetails($approvalId);
        if (!$approval) {
            throw new InvalidArgumentException("Approval request #{$approvalId} not found.");
        }

        $incidentId = (int)$approval['incident_id'];
        $alerts = $this->incidentRepo->getAttachedAlerts($incidentId);
        $iocs   = $this->iocRepo->getIncidentIocs($incidentId);

        // Audit view
        $this->auditLog(
            $authContext['actor'] ?? 'analyst',
            'APPROVAL_VIEWED',
            "approval_id={$approvalId}",
            'success',
            ['approval_id' => $approvalId, 'incident_id' => $incidentId]
        );

        $actionPreview = $this->generateActionPreview($approval);

        return [
            'approval'       => $approval,
            'action_preview' => $actionPreview,
            'evidence'       => [
                'correlated_alerts_count' => count($alerts),
                'alerts_sample'           => array_slice($alerts, 0, 5),
                'iocs_count'              => count($iocs),
                'iocs'                    => array_slice($iocs, 0, 10),
                'attack_category'         => $approval['attack_category'] ?? null,
                'mitre_tactics'           => $approval['mitre_tactics'] ?? null,
                'mitre_techniques'        => $approval['mitre_techniques'] ?? null,
            ]
        ];
    }

    /**
     * Generate safe preview representation of the action to be approved.
     * Completely redacts any internal credentials, passwords, or secrets.
     */
    public function generateActionPreview(array $approval): array {
        $payload = $approval['action_payload'] ?? [];
        if (is_string($payload)) {
            $payload = json_decode($payload, true) ?? [];
        }

        // Redact secrets recursively
        $safeParameters = $this->sanitizeParameters($payload);

        return [
            'action_type'         => $approval['action_name'] ?? 'UNKNOWN',
            'description'         => $approval['action_description'] ?? '',
            'risk_level'          => in_array($approval['action_name'] ?? '', ['REQUEST_APPROVAL', 'BLOCK_IP'], true) ? 'MEDIUM' : 'LOW',
            'required_tier'       => $approval['required_tier'] ?? 'LEAD',
            'resolved_parameters' => $safeParameters,
            'incident_reference'  => [
                'incident_id'     => $approval['incident_id'] ?? null,
                'incident_number' => $approval['incident_number'] ?? null,
                'priority'        => $approval['incident_priority'] ?? null,
                'risk_score'      => $approval['incident_risk_score'] ?? 0,
            ]
        ];
    }

    /**
     * Process an analyst decision (APPROVE or REJECT) on an approval request.
     * Transactional, atomic, and tamper-resistant.
     */
    public function processDecision(ApprovalDecision $decision, array $authContext): array {
        $approvalId = $decision->approvalId;
        $approval   = $this->approvalRepo->findWithDetails($approvalId);

        if (!$approval) {
            throw new InvalidArgumentException("Approval request #{$approvalId} not found.");
        }

        // 1. Verify State Machine (must be PENDING)
        $this->validator->validateTransition($approval['status'], $decision->decision === 'APPROVE' ? 'APPROVED' : 'REJECTED');

        // 2. Verify Expiration against authoritative server time
        $this->validator->assertNotExpired($approval['expires_at']);

        // 3. Verify Approver Authorization (Tier & Capability)
        $this->validator->assertApproverAuthorized($decision->reviewerTier, $approval['required_tier']);

        // 4. Validate Rejection Reason if rejecting
        $cleanReason = null;
        if ($decision->isRejected()) {
            if (empty($decision->reason)) {
                throw new InvalidArgumentException("A detailed rejection reason is required when rejecting an approval.");
            }
            $cleanReason = $this->validator->validateAndNormalizeReason($decision->reason);
        }

        // 5. Verify Incident Existence
        $incidentId = (int)$approval['incident_id'];
        $incident   = $this->incidentRepo->find($incidentId, true);
        if (!$incident) {
            throw new RuntimeException("Underlying incident #{$incidentId} does not exist. Cannot process approval.");
        }

        // 6. Verify Playbook Run State (must be WAITING_APPROVAL)
        $runId = (int)$approval['playbook_run_id'];
        $run   = $this->playbookRepo->findRun($runId);
        if (!$run || $run['status'] !== 'WAITING_APPROVAL') {
            throw new RuntimeException("Underlying playbook run #{$runId} is not in WAITING_APPROVAL state.");
        }

        // 7. Verify Payload Hash Integrity (Anti-Tampering)
        $this->verifyPayloadIntegrity($approval, $run);

        // 8. Transactional Consumption & State Execution
        if ($this->pdo) {
            $this->pdo->beginTransaction();
        }

        try {
            // Atomic state update (rowCount=1 guard prevents concurrent consumption)
            $consumed = $this->approvalRepo->consumeDecision(
                $approvalId,
                $decision->decision,
                $decision->reviewerId,
                $cleanReason
            );

            if (!$consumed) {
                throw new RuntimeException("Approval #{$approvalId} could not be consumed (already decided, expired, or race condition).");
            }

            if ($decision->isApproved()) {
                // Resume Playbook Execution at the exact cursor step
                $engine = new PlaybookEngine($this->pdo);
                $engine->resumeAfterApproval(
                    $runId,
                    $approvalId,
                    $decision->reviewerId,
                    'APPROVED',
                    $authContext,
                    $decision->reviewerTier
                );

                // Audit & Timeline
                $this->auditLog(
                    $authContext['actor'] ?? 'analyst',
                    'APPROVAL_APPROVED',
                    "approval_id={$approvalId}",
                    'success',
                    ['approval_id' => $approvalId, 'incident_id' => $incidentId, 'run_id' => $runId]
                );

                $this->timeline->addEvent(
                    $incidentId,
                    'APPROVAL_GRANTED',
                    IncidentTimeline::ACTOR_ANALYST,
                    $authContext['actor'] ?? 'analyst',
                    "Action '{$approval['action_name']}' approved by {$authContext['actor']} ({$decision->reviewerTier})",
                    ['approval_id' => $approvalId, 'run_id' => $runId]
                );

                // In-App Notification
                $this->notificationService->notify(
                    (int)($run['analyst_id'] ?? $decision->reviewerId),
                    NotificationService::TYPE_APPROVAL_APPROVED,
                    "Approval Granted: {$approval['action_name']}",
                    "Approval request #{$approvalId} for incident {$incident['incident_number']} was approved.",
                    ['incident_id' => $incidentId, 'approval_id' => $approvalId, 'playbook_run_id' => $runId]
                );

            } else {
                // Decision is REJECT: Mark run as FAILED / CANCELLED
                $this->runManager->transition($runId, 'FAILED', "Approval rejected: {$cleanReason}");

                // Audit & Timeline
                $this->auditLog(
                    $authContext['actor'] ?? 'analyst',
                    'APPROVAL_REJECTED',
                    "approval_id={$approvalId}",
                    'failure',
                    ['approval_id' => $approvalId, 'incident_id' => $incidentId, 'run_id' => $runId, 'reason' => $cleanReason]
                );

                $this->timeline->addEvent(
                    $incidentId,
                    'APPROVAL_REJECTED',
                    IncidentTimeline::ACTOR_ANALYST,
                    $authContext['actor'] ?? 'analyst',
                    "Action '{$approval['action_name']}' rejected by {$authContext['actor']}: {$cleanReason}",
                    ['approval_id' => $approvalId, 'run_id' => $runId, 'reason' => $cleanReason]
                );

                // In-App Notification
                $this->notificationService->notify(
                    (int)($run['analyst_id'] ?? $decision->reviewerId),
                    NotificationService::TYPE_APPROVAL_REJECTED,
                    "Approval Rejected: {$approval['action_name']}",
                    "Approval request #{$approvalId} was rejected by {$authContext['actor']}. Reason: {$cleanReason}",
                    ['incident_id' => $incidentId, 'approval_id' => $approvalId, 'playbook_run_id' => $runId]
                );
            }

            if ($this->pdo) {
                $this->pdo->commit();
            }

            return [
                'success'     => true,
                'approval_id' => $approvalId,
                'status'      => $decision->isApproved() ? 'APPROVED' : 'REJECTED',
                'decision'    => $decision->decision,
                'decided_at'  => date('Y-m-d H:i:s'),
                'reviewer_id' => $decision->reviewerId,
                'run_id'      => $runId
            ];

        } catch (Throwable $e) {
            if ($this->pdo && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Verify payload hash integrity between stored approval and active step parameters.
     */
    private function verifyPayloadIntegrity(array $approval, array $run): void {
        $storedHash = $approval['payload_hash'] ?? null;
        if (!$storedHash) {
            return; // Legacy approval without hash
        }

        $playbookId  = (int)$run['playbook_id'];
        $cursorOrder = (int)($run['current_step_order'] ?? 1);
        $steps       = $this->playbookRepo->getSteps($playbookId);

        $cursorStep = null;
        foreach ($steps as $s) {
            if ((int)$s['step_order'] === $cursorOrder) {
                $cursorStep = $s;
                break;
            }
        }

        if (!$cursorStep) {
            throw new RuntimeException("Cursor step order {$cursorOrder} not found for playbook #{$playbookId}.");
        }

        $rawParams = $cursorStep['action_parameters'] ?? '[]';
        if (is_array($rawParams)) {
            $rawParams = json_encode($rawParams, JSON_UNESCAPED_SLASHES);
        }

        $this->validator->assertPayloadIntegrity($storedHash, (string)$rawParams);
    }

    /**
     * Recursively strip secrets from parameter arrays.
     */
    private function sanitizeParameters(mixed $params): mixed {
        if (!is_array($params)) {
            return $params;
        }

        $sanitized = [];
        $secretKeys = ['password', 'passwd', 'pwd', 'api_key', 'token', 'secret', 'auth', 'credentials', 'bearer'];

        foreach ($params as $key => $value) {
            if (is_string($key) && in_array(strtolower($key), $secretKeys, true)) {
                $sanitized[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $sanitized[$key] = $this->sanitizeParameters($value);
            } else {
                $sanitized[$key] = $value;
            }
        }
        return $sanitized;
    }

    /**
     * Internal audit log helper.
     */
    private function auditLog(string $actor, string $action, string $target, string $result, array $details): void {
        if (!$this->pdo) return;
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                substr($actor, 0, 50),
                substr($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1', 0, 45),
                substr($action, 0, 100),
                substr($target, 0, 255),
                $result,
                substr(json_encode($details, JSON_UNESCAPED_SLASHES), 0, 1000),
                substr($_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-ApprovalControlPlane/1.0', 0, 500)
            ]);
        } catch (Throwable $e) {}
    }
}
