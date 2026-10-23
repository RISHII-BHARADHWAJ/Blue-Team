<?php
/**
 * ThreatPulse SOAR - Incident Manager
 * 
 * Core domain service orchestrating the incident lifecycle:
 * - Incident creation & unique numbering
 * - Alert-to-incident correlation & attachment
 * - State machine transition enforcement
 * - Severity escalation & priority mapping
 * - Analyst assignment & manual escalation
 * - Append-only timeline logging
 */

require_once __DIR__ . '/AlertSchema.php';
require_once __DIR__ . '/IncidentRepository.php';
require_once __DIR__ . '/IncidentStateMachine.php';
require_once __DIR__ . '/IncidentNumberGenerator.php';
require_once __DIR__ . '/IncidentTimeline.php';
require_once __DIR__ . '/CorrelationEngine.php';
require_once __DIR__ . '/SoarAuth.php';
require_once __DIR__ . '/notifications/NotificationService.php';

final class IncidentAssignmentConflict extends RuntimeException {}

class IncidentManager {
    private ?PDO $pdo;
    private IncidentRepository $repository;
    private IncidentTimeline $timeline;
    private CorrelationEngine $correlationEngine;

    /**
     * Priority mapping table from severity.
     */
    private const PRIORITY_MAP = [
        'CRITICAL' => 'P1',
        'HIGH'     => 'P2',
        'MEDIUM'   => 'P3',
        'LOW'      => 'P4',
        'INFO'     => 'P4',
    ];

    /**
     * Severity hierarchy for comparison and escalation.
     */
    private const SEVERITY_WEIGHTS = [
        'CRITICAL' => 5,
        'HIGH'     => 4,
        'MEDIUM'   => 3,
        'LOW'      => 2,
        'INFO'     => 1,
    ];

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
        $this->repository = new IncidentRepository($pdo);
        $this->timeline = new IncidentTimeline($pdo);
        $this->correlationEngine = new CorrelationEngine($this->repository);
    }

    /**
     * Create a new security incident.
     * 
     * @param array $params Incident parameters (title, description, severity, priority, category)
     * @param ?AlertSchema $initialAlert Optional initial canonical alert
     * @param ?int $logId Optional SIEM log ID
     * @param string $actor Submitting identity
     * @param string $correlationRule Name of rule that triggered creation
     * @return array Created incident record with metadata
     */
    public function createIncident(
        array $params,
        ?AlertSchema $initialAlert = null,
        ?int $logId = null,
        string $actor = 'system',
        string $correlationRule = 'INITIAL_ALERT'
    ): array {
        $inTx = $this->pdo && $this->pdo->inTransaction();
        if ($this->pdo && !$inTx) {
            $this->pdo->beginTransaction();
        }

        try {
            // 1. Generate unique incident number (INC-YYYY-NNNN)
            $incidentNumber = IncidentNumberGenerator::generate($this->pdo);

            // 2. Resolve Severity and Priority
            $severity = strtoupper(trim($params['severity'] ?? ($initialAlert ? $initialAlert->severity : 'MEDIUM')));
            if (!in_array($severity, AlertSchema::SEVERITIES, true)) {
                $severity = 'MEDIUM';
            }
            $priority = self::PRIORITY_MAP[$severity] ?? 'P3';

            $title = trim($params['title'] ?? 'Security Incident');
            $description = trim($params['description'] ?? ($initialAlert ? $initialAlert->message : ''));
            $category = trim($params['attack_category'] ?? ($initialAlert ? $initialAlert->category : 'Other'));

            // 3. Insert Incident
            $incidentId = $this->repository->create([
                'incident_number'  => $incidentNumber,
                'title'            => $title,
                'description'      => $description,
                'severity'         => $severity,
                'status'           => IncidentStateMachine::STATE_NEW,
                'priority'         => $priority,
                'is_simulated'     => !empty($params['is_simulated']),
                'risk_score'       => 0, // Phase 5 will implement real risk scoring
                'assigned_to'      => $params['assigned_to'] ?? null,
                'lead_analyst'     => $params['lead_analyst'] ?? null,
                'attack_category'  => $category,
                'mitre_tactics'    => $params['mitre_tactics'] ?? ($initialAlert ? $initialAlert->mitre_tactic : null),
                'mitre_techniques' => $params['mitre_techniques'] ?? ($initialAlert ? $initialAlert->mitre_technique : null),
            ]);

            // 4. Attach initial alert if provided
            if ($logId !== null) {
                $this->repository->attachAlert($incidentId, $logId, $correlationRule);
                $this->timeline->addEvent(
                    $incidentId,
                    'ALERT_ADDED',
                    IncidentTimeline::ACTOR_SYSTEM,
                    $actor,
                    "Initial alert #{$logId} associated with incident",
                    ['log_id' => $logId, 'correlation_rule' => $correlationRule]
                );
            }

            // 5. Add initial timeline entry for incident creation
            $this->timeline->addEvent(
                $incidentId,
                'STATUS_CHANGE',
                IncidentTimeline::ACTOR_SYSTEM,
                $actor,
                "Incident {$incidentNumber} created with status NEW",
                ['initial_status' => 'NEW', 'severity' => $severity, 'priority' => $priority]
            );

            // 6. Security Audit Log
            $this->auditLog($actor, 'create_incident', $incidentNumber, 'success', [
                'incident_id' => $incidentId,
                'severity'    => $severity,
                'title'       => $title
            ]);

            if ($this->pdo && !$inTx) {
                $this->pdo->commit();
            }

            return $this->getIncident($incidentId);

        } catch (Exception $e) {
            if ($this->pdo && !$inTx && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Attach a SIEM alert record to an existing incident.
     */
    public function attachAlert(
        int $incidentId,
        int $logId,
        string $correlationRule = 'CORRELATION',
        string $actor = 'system',
        ?AlertSchema $alert = null
    ): array {
        $inTx = $this->pdo && $this->pdo->inTransaction();
        if ($this->pdo && !$inTx) {
            $this->pdo->beginTransaction();
        }

        try {
            $incident = $this->repository->find($incidentId, true);
            if (!$incident) {
                throw new InvalidArgumentException("Incident #{$incidentId} does not exist.");
            }

            // Verify incident is active
            if (!IncidentStateMachine::isActive($incident['status'])) {
                throw new InvalidStateTransitionException("Cannot attach alerts to non-active incident {$incident['incident_number']} (Status: {$incident['status']}).");
            }

            // Attach to junction
            $this->repository->attachAlert($incidentId, $logId, $correlationRule);

            // Log to timeline
            $this->timeline->addEvent(
                $incidentId,
                'ALERT_ADDED',
                $actor === 'system' ? IncidentTimeline::ACTOR_SYSTEM : IncidentTimeline::ACTOR_ANALYST,
                $actor,
                "Alert #{$logId} attached via rule {$correlationRule}",
                ['log_id' => $logId, 'rule' => $correlationRule]
            );

            // Evaluate severity escalation if alert severity is higher than incident severity
            if ($alert !== null) {
                $alertWeight = self::SEVERITY_WEIGHTS[$alert->severity] ?? 1;
                $incWeight = self::SEVERITY_WEIGHTS[$incident['severity']] ?? 1;

                if ($alertWeight > $incWeight) {
                    $newPriority = self::PRIORITY_MAP[$alert->severity] ?? $incident['priority'];
                    $this->repository->update($incidentId, [
                        'severity' => $alert->severity,
                        'priority' => $newPriority
                    ]);

                    $this->timeline->addEvent(
                        $incidentId,
                        'SEVERITY_CHANGE',
                        IncidentTimeline::ACTOR_SYSTEM,
                        'CorrelationEngine',
                        "Severity escalated from {$incident['severity']} to {$alert->severity} due to attached alert #{$logId}",
                        ['old_severity' => $incident['severity'], 'new_severity' => $alert->severity]
                    );
                }
            }

            if ($this->pdo && !$inTx) {
                $this->pdo->commit();
            }

            return $this->getIncident($incidentId);

        } catch (Exception $e) {
            if ($this->pdo && !$inTx && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Transition an incident to a new lifecycle status with validation and auditing.
     */
    public function changeStatus(int $incidentId, string $newStatus, string $actor, ?string $reason = null): array {
        $newStatusUpper = strtoupper(trim($newStatus));

        $inTx = $this->pdo && $this->pdo->inTransaction();
        if ($this->pdo && !$inTx) {
            $this->pdo->beginTransaction();
        }

        try {
            $incident = $this->repository->find($incidentId, true);
            if (!$incident) {
                throw new InvalidArgumentException("Incident #{$incidentId} does not exist.");
            }

            $currentStatus = $incident['status'];

            // 1. Assert State Machine Transition Validity
            IncidentStateMachine::assertValidTransition($currentStatus, $newStatusUpper);

            // 2. Check Authorization
            $userTier = SoarAuth::getContext($this->pdo)['tier'];
            if ($newStatusUpper === IncidentStateMachine::STATE_CLOSED && !SoarAuth::hasPermission($userTier, 'close_incidents')) {
                throw new DomainException("Permission denied: Tier {$userTier} cannot close incidents. Requires LEAD or ADMIN.");
            }

            // 3. Prepare Update Payload
            $updateData = ['status' => $newStatusUpper];
            if ($newStatusUpper === IncidentStateMachine::STATE_CONTAINED && empty($incident['contained_at'])) {
                $updateData['contained_at'] = date('Y-m-d H:i:s');
            } elseif ($newStatusUpper === IncidentStateMachine::STATE_RESOLVED && empty($incident['resolved_at'])) {
                $updateData['resolved_at'] = date('Y-m-d H:i:s');
            } elseif ($newStatusUpper === IncidentStateMachine::STATE_CLOSED && empty($incident['closed_at'])) {
                $updateData['closed_at'] = date('Y-m-d H:i:s');
            }

            $this->repository->update($incidentId, $updateData);

            // 4. Timeline Entry
            $this->timeline->addEvent(
                $incidentId,
                'STATUS_CHANGE',
                IncidentTimeline::ACTOR_ANALYST,
                $actor,
                "Status changed from {$currentStatus} to {$newStatusUpper}" . ($reason ? ": $reason" : ""),
                ['old_status' => $currentStatus, 'new_status' => $newStatusUpper, 'reason' => $reason]
            );

            // 5. Audit Log
            $this->auditLog($actor, 'change_incident_status', $incident['incident_number'], 'success', [
                'incident_id' => $incidentId,
                'old_status'  => $currentStatus,
                'new_status'  => $newStatusUpper,
                'reason'      => $reason
            ]);

            if ($this->pdo && !$inTx) {
                $this->pdo->commit();
            }

            return $this->getIncident($incidentId);

        } catch (Exception $e) {
            if ($this->pdo && !$inTx && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Assign an incident to an analyst.
     */
    public function assignIncident(int $incidentId, int $analystId, string $actor, int|null|false $expectedAssignee = false): array {
        $inTx = $this->pdo && $this->pdo->inTransaction();
        $savepoint = 'assignment_' . bin2hex(random_bytes(8));
        if ($this->pdo) {
            if (!$inTx) $this->pdo->beginTransaction();
            else $this->pdo->exec("SAVEPOINT $savepoint");
        }

        try {
            $incident = $this->repository->find($incidentId, true);
            if (!$incident) {
                throw new InvalidArgumentException("Incident #{$incidentId} does not exist.");
            }

            $targetUser = $this->repository->findUserById($analystId);
            if (!$targetUser) {
                throw new InvalidArgumentException("Target user ID #{$analystId} does not exist.");
            }
            // Assignment must not delegate incident responsibility to an account
            // with no analyst triage capability (e.g. ordinary 'user' role).
            $targetTier = SoarAuth::resolveTier($targetUser['role'] ?? null);
            if (!SoarAuth::hasPermission($targetTier, 'change_status_normal')) {
                throw new InvalidArgumentException("Target user is not an eligible incident analyst.");
            }

            $previous = $incident['assigned_to'] === null ? null : (int)$incident['assigned_to'];
            if ($previous === $analystId) {
                // Preserve current locked case fields even in a caller's older read snapshot.
                $result = array_replace($this->getIncident($incidentId) ?? [], $incident);
                if ($this->pdo) {
                    if (!$inTx) $this->pdo->commit();
                    else $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
                }
                return $result;
            }
            if ($expectedAssignee !== false && $previous !== $expectedAssignee) {
                throw new IncidentAssignmentConflict('Case assignment changed since this page was loaded. Reload the case before assigning it.');
            }

            $this->repository->update($incidentId, ['assigned_to' => $analystId]);

            $this->timeline->addEvent(
                $incidentId,
                'NOTE_ADDED',
                IncidentTimeline::ACTOR_ANALYST,
                $actor,
                "Incident assigned to {$targetUser['username']}",
                ['previous_assigned_to' => $previous, 'assigned_to_user_id' => $analystId, 'username' => $targetUser['username']]
            );

            $this->auditLog($actor, 'assign_incident', $incident['incident_number'], 'success', [
                'incident_id' => $incidentId,
                'previous_assigned_to' => $previous,
                'assigned_to_user_id' => $analystId,
                'assigned_to' => $targetUser['username']
            ], true);

            $label = !empty($incident['is_simulated']) ? 'SIMULATED: ' : '';
            $sent = (new NotificationService($this->pdo))->notify($analystId, 'INCIDENT_ASSIGNED',
                $label . 'Case assigned: ' . $incident['incident_number'],
                $label . $actor . ' assigned ' . $incident['incident_number'] . ' to you. Open the case to review its evidence and next steps.',
                ['incident_id'=>$incidentId]);
            if (!$sent) throw new RuntimeException('Assignment notification could not be saved.');

            $result = $this->getIncident($incidentId);
            if ($this->pdo) {
                if (!$inTx) $this->pdo->commit();
                else $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
            }

            return $result;

        } catch (Throwable $e) {
            if ($this->pdo && $this->pdo->inTransaction()) {
                if (!$inTx) $this->pdo->rollBack();
                else {
                    $this->pdo->exec("ROLLBACK TO SAVEPOINT $savepoint");
                    $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
                }
            }
            throw $e;
        }
    }

    /**
     * Manually escalate an existing SIEM log record into a security incident.
     */
    public function escalateAlertToIncident(
        int $logId,
        string $actor,
        ?string $customTitle = null,
        ?string $customDescription = null
    ): array {
        $this->repository->assertNotSimulated($logId);

        // 1. Check if alert is already attached to an active incident
        $existingLink = $this->repository->isLogAttached($logId);
        if ($existingLink && IncidentStateMachine::isActive($existingLink['status'])) {
            return [
                'success'         => true,
                'action'          => 'existing_incident_returned',
                'incident'        => $this->getIncident((int)$existingLink['incident_id']),
                'message'         => "Alert #{$logId} is already associated with active incident {$existingLink['incident_number']}."
            ];
        }

        // 2. Fetch log record
        $stmt = $this->pdo ? $this->pdo->prepare("SELECT * FROM logs WHERE id = ?") : null;
        if ($stmt) {
            $stmt->execute([$logId]);
            $logRow = $stmt->fetch();
        } else {
            $logRow = [
                'id' => $logId, 'source_ip' => '198.51.100.1', 'severity' => 'HIGH', 'category' => 'SSH',
                'message' => 'Manual escalation test', 'timestamp' => date('Y-m-d H:i:s')
            ];
        }

        if (!$logRow) {
            throw new InvalidArgumentException("Log record #{$logId} not found.");
        }

        // 3. Normalize into canonical alert
        require_once __DIR__ . '/AlertNormalizer.php';
        $normalizer = new AlertNormalizer();
        $canonicalAlert = $normalizer->normalize($logRow);

        // 4. Create Incident
        $title = $customTitle ?: $this->correlationEngine->generateIncidentTitle(
            $canonicalAlert->category,
            $canonicalAlert->source_ip,
            $canonicalAlert->severity
        );

        $incident = $this->createIncident([
            'title'           => $title,
            'description'     => $customDescription ?: "Manually escalated from SIEM log #{$logId}: " . $canonicalAlert->message,
            'severity'        => $canonicalAlert->severity,
            'attack_category' => $canonicalAlert->category
        ], $canonicalAlert, $logId, $actor, 'MANUAL_ESCALATION');

        return [
            'success'  => true,
            'action'   => 'new_incident_created',
            'incident' => $incident,
            'message'  => "Log #{$logId} escalated to new incident {$incident['incident_number']}."
        ];
    }

    /**
     * Process an incoming alert through the complete Correlation + Incident pipeline.
     */
    public function processAlert(AlertSchema|array $alert, ?int $logId = null, string $actor = 'system'): array {
        $canonical = is_array($alert) ? AlertSchema::fromArray($alert) : $alert;

        // 1. Evaluate correlation decision
        $decision = $this->correlationEngine->evaluate($canonical);

        // 2. Branch according to decision
        if ($decision['decision'] === 'ATTACH' && !empty($decision['incident_id'])) {
            $incident = $this->attachAlert(
                (int)$decision['incident_id'],
                $logId ?: 0,
                implode('+', $decision['rules']),
                $actor,
                $canonical
            );

            return [
                'decision'    => 'ATTACH',
                'incident'    => $incident,
                'correlation' => $decision
            ];
        }

        if ($decision['decision'] === 'CREATE') {
            $incident = $this->createIncident([
                'title'           => $decision['suggested_title'],
                'description'     => $canonical->message,
                'severity'        => $canonical->severity,
                'attack_category' => $canonical->category,
            ], $canonical, $logId, $actor, 'CORRELATION_CREATE');

            return [
                'decision'    => 'CREATE',
                'incident'    => $incident,
                'correlation' => $decision
            ];
        }

        return [
            'decision'    => 'IGNORE',
            'incident'    => null,
            'correlation' => $decision
        ];
    }

    /**
     * Retrieve complete incident record with attached alerts and timeline.
     */
    public function getIncident(int $incidentId): ?array {
        $incident = $this->repository->find($incidentId);
        if (!$incident) {
            return null;
        }

        $incident['alerts'] = $this->repository->getAttachedAlerts($incidentId);
        $incident['timeline'] = $this->timeline->getEvents($incidentId);
        $incident['iocs'] = $this->repository->getIncidentIocs($incidentId);

        return $incident;
    }

    /**
     * List incidents with filters and pagination.
     */
    public function listIncidents(array $filters = [], int $limit = 50, int $offset = 0): array {
        return $this->repository->listIncidents($filters, $limit, $offset);
    }

    /**
     * Record security audit log entry.
     */
    private function auditLog(string $analyst, string $action, string $target, string $result, array $details, bool $required = false): void {
        if (!$this->pdo) {
            return;
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-Incident-Manager/1.0';

        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                substr($analyst, 0, 50),
                substr($ip, 0, 45),
                substr($action, 0, 100),
                substr($target, 0, 255),
                $result,
                substr(json_encode($details, JSON_UNESCAPED_SLASHES), 0, 1000),
                substr($ua, 0, 500)
            ]);
        } catch (Exception $e) {
            if ($required) throw $e;
        }
    }
}
