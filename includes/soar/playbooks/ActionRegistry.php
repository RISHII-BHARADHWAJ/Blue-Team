<?php
/**
 * ThreatPulse SOAR - Action Registry
 *
 * The ONLY authoritative source for allowed playbook action types.
 *
 * SECURITY GUARANTEE:
 * - Action types are an explicit, hard-coded allowlist.
 * - Handler class names are hard-coded here and NEVER read from database/client input.
 * - A database field containing "ENRICH_IOCS" selects the handler via this registry.
 * - A database field containing "MyMaliciousClass" is REJECTED — it is not in the registry.
 * - Arbitrary execution (eval, exec, shell_exec, dynamic includes) is ABSENT from this codebase.
 */

require_once __DIR__ . '/ActionDefinition.php';
require_once __DIR__ . '/ActionResult.php';

// ---- Action Handler Interface -----------------------------------------------
interface PlaybookActionHandler {
    /**
     * Execute the action (or simulate in dry-run mode).
     *
     * @param array $parameters Resolved (template-substituted) action parameters
     * @param array $context    Immutable playbook context snapshot
     * @param bool  $dryRun     True = simulate, no side effects
     * @return ActionResult
     */
    public function execute(array $parameters, array $context, bool $dryRun = false): ActionResult;
}

// ---- Concrete Action Handlers -----------------------------------------------

class EnrichIocsAction implements PlaybookActionHandler {
    private ?PDO $pdo;
    public function __construct(?PDO $pdo = null) { $this->pdo = $pdo; }

    public function execute(array $parameters, array $context, bool $dryRun = false): ActionResult {
        $incidentId = (int)($parameters['incident_id'] ?? $context['incident']['id'] ?? 0);
        if (!$incidentId) {
            return new ActionResult(ActionResult::STATUS_FAILED, 'incident_id is required.', [], $dryRun);
        }
        if ($dryRun) {
            $iocCount = count($context['iocs'] ?? []);
            return new ActionResult(ActionResult::STATUS_SUCCESS, "Would enrich {$iocCount} IOC(s) for incident #{$incidentId}.", [], true);
        }
        if ($this->pdo) {
            require_once __DIR__ . '/../IncidentIocService.php';
            $svc = new IncidentIocService($this->pdo);
            $result = $svc->processIncidentIocs($incidentId, true, 'playbook-engine');
            return new ActionResult(ActionResult::STATUS_SUCCESS, "Enriched IOCs for incident #{$incidentId}.", $result, false);
        }
        return new ActionResult(ActionResult::STATUS_FAILED, 'Database unavailable.', [], $dryRun);
    }
}

class CollectIncidentContextAction implements PlaybookActionHandler {
    private ?PDO $pdo;
    public function __construct(?PDO $pdo = null) { $this->pdo = $pdo; }

    public function execute(array $parameters, array $context, bool $dryRun = false): ActionResult {
        if ($dryRun) {
            return new ActionResult(ActionResult::STATUS_SUCCESS, 'Would collect incident context snapshot.', [], true);
        }
        $snapshot = [
            'incident_id'     => $context['incident']['id'] ?? null,
            'incident_number' => $context['incident']['incident_number'] ?? null,
            'severity'        => $context['incident']['severity'] ?? null,
            'priority'        => $context['incident']['priority'] ?? null,
            'risk_score'      => $context['incident']['risk_score'] ?? null,
            'alert_count'     => count($context['alerts'] ?? []),
            'ioc_count'       => count($context['iocs'] ?? []),
            'collected_at'    => date('Y-m-d H:i:s'),
        ];
        return new ActionResult(ActionResult::STATUS_SUCCESS, 'Incident context snapshot collected.', $snapshot, false, ['context_snapshot']);
    }
}

class AddIncidentNoteAction implements PlaybookActionHandler {
    private ?PDO $pdo;
    public function __construct(?PDO $pdo = null) { $this->pdo = $pdo; }

    public function execute(array $parameters, array $context, bool $dryRun = false): ActionResult {
        $note = trim($parameters['note'] ?? '');
        if ($note === '') {
            return new ActionResult(ActionResult::STATUS_FAILED, 'Parameter "note" is required.', [], $dryRun);
        }
        if ($dryRun) {
            return new ActionResult(ActionResult::STATUS_SUCCESS, 'Would add case note to incident.', ['note_preview' => substr($note, 0, 100)], true);
        }
        $incidentId = (int)($context['incident']['id'] ?? 0);
        if ($this->pdo && $incidentId) {
            $authorId = (int)($context['analyst']['id'] ?? 0);
            if ($authorId < 1) {
                return new ActionResult(ActionResult::STATUS_FAILED, 'A verified analyst account is required to author a case note.', [], false);
            }
            require_once __DIR__ . '/../CaseNoteService.php';
            try {
                $saved = (new CaseNoteService($this->pdo))->add($incidentId, $authorId, $note);
                return new ActionResult(ActionResult::STATUS_SUCCESS, 'Case note added.', ['note_id' => $saved['id']], false);
            } catch (Throwable $e) {
                error_log('Playbook case note failed: ' . $e->getMessage());
                return new ActionResult(ActionResult::STATUS_FAILED, 'Case note could not be saved with verified attribution.', [], false);
            }
        }
        return new ActionResult(ActionResult::STATUS_FAILED, 'Database unavailable.', [], $dryRun);
    }
}

class RequestApprovalAction implements PlaybookActionHandler {
    private ?PDO $pdo;
    public function __construct(?PDO $pdo = null) { $this->pdo = $pdo; }

    public function execute(array $parameters, array $context, bool $dryRun = false): ActionResult {
        if ($dryRun && !empty($context['incident']['is_simulated'])) {
            return new ActionResult(ActionResult::STATUS_SUCCESS, 'Would request approval; simulated cases do not create approval requests.', [], true);
        }
        if ($dryRun) {
            return new ActionResult(ActionResult::STATUS_SUCCESS, 'Would request analyst approval; dry-run does not create an approval request.', [], true);
        }
        // Actual approval creation is handled by PlaybookStepExecutor.
        // This handler signals the need for it.
        return new ActionResult(ActionResult::STATUS_WAITING_APPROVAL, 'Approval gate reached. Execution paused pending human approval.', [], false);
    }
}

class NotifyAnalystAction implements PlaybookActionHandler {
    private ?PDO $pdo;
    public function __construct(?PDO $pdo = null) { $this->pdo = $pdo; }

    public function execute(array $parameters, array $context, bool $dryRun = false): ActionResult {
        $title   = trim($parameters['title']   ?? 'Playbook Notification');
        $message = trim($parameters['message'] ?? 'A playbook requires your attention.');
        if ($dryRun) {
            return new ActionResult(ActionResult::STATUS_SUCCESS, "Would notify analyst: \"{$title}\".", [], true);
        }
        $incidentId = (int)($context['incident']['id'] ?? 0);
        $analystId  = (int)($context['analyst']['id'] ?? 0);
        if ($this->pdo && $analystId) {
            require_once __DIR__.'/../notifications/NotificationService.php';
            $sent=(new NotificationService($this->pdo))->notify($analystId,'PLAYBOOK_NOTIFICATION',$title,$message,[
                'incident_id'=>$incidentId ?: null, 'playbook_run_id'=>$context['playbook_run']['id'] ?? null,
            ]);
            if (!$sent) return new ActionResult(ActionResult::STATUS_FAILED,'Could not save the analyst notification.',[],false);
            return new ActionResult(ActionResult::STATUS_SUCCESS, 'Analyst notified.', ['notification_id' => (int)$this->pdo->lastInsertId()], false);
        }
        return new ActionResult(ActionResult::STATUS_SKIPPED, 'No target analyst resolved from context.', [], $dryRun);
    }
}

class CreateEvidenceRecordAction implements PlaybookActionHandler {
    private ?PDO $pdo;
    public function __construct(?PDO $pdo = null) { $this->pdo = $pdo; }

    public function execute(array $parameters, array $context, bool $dryRun = false): ActionResult {
        $title   = trim($parameters['title']       ?? 'Playbook Evidence');
        $content = trim($parameters['content']     ?? json_encode($context['incident'] ?? []));
        $type    = strtoupper(trim($parameters['evidence_type'] ?? 'LOG_SNIPPET'));
        $allowed = ['LOG_SNIPPET','NETWORK_PCAP','FILE_HASH','MEMORY_DUMP_META','HTTP_REQUEST_PAYLOAD','SCREENSHOT'];
        if (!in_array($type, $allowed, true)) { $type = 'LOG_SNIPPET'; }

        if ($dryRun) {
            return new ActionResult(ActionResult::STATUS_SUCCESS, "Would create evidence record \"{$title}\" of type {$type}.", [], true);
        }
        $hash       = hash('sha256', $content . microtime(true));
        $incidentId = (int)($context['incident']['id'] ?? 0);
        if ($this->pdo && $incidentId) {
            $stmt = $this->pdo->prepare("
                INSERT INTO evidence (incident_id, evidence_type, title, data_hash, content_text)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$incidentId, $type, substr($title, 0, 255), $hash, $content]);
            $evidenceId = (int)$this->pdo->lastInsertId();
            return new ActionResult(ActionResult::STATUS_SUCCESS, "Evidence record #{$evidenceId} created.", ['evidence_id' => $evidenceId, 'hash' => $hash], false, [$hash]);
        }
        return new ActionResult(ActionResult::STATUS_FAILED, 'Database unavailable.', [], $dryRun);
    }
}

// ---- Registry ---------------------------------------------------------------

class ActionRegistry {

    // Static allowlist: maps action_type string → handler class name.
    // Handler class names are NEVER read from user input, database, or playbook JSON.
    private static array $allowlist = [
        'ENRICH_IOCS'              => EnrichIocsAction::class,
        'COLLECT_INCIDENT_CONTEXT' => CollectIncidentContextAction::class,
        'ADD_INCIDENT_NOTE'        => AddIncidentNoteAction::class,
        'REQUEST_APPROVAL'         => RequestApprovalAction::class,
        'NOTIFY_ANALYST'           => NotifyAnalystAction::class,
        'CREATE_EVIDENCE_RECORD'   => CreateEvidenceRecordAction::class,
    ];

    // Static definitions
    private static array $definitions = [];

    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
        self::initDefinitions();
    }

    private static function initDefinitions(): void {
        if (!empty(self::$definitions)) return;
        self::$definitions = [
            'ENRICH_IOCS' => new ActionDefinition(
                'ENRICH_IOCS', 'Enrich all IOCs associated with the incident.', 'LOW', false,
                ['incident_id'], 30, 1, EnrichIocsAction::class
            ),
            'COLLECT_INCIDENT_CONTEXT' => new ActionDefinition(
                'COLLECT_INCIDENT_CONTEXT', 'Collect a snapshot of the current incident context.', 'LOW', false,
                [], 15, 0, CollectIncidentContextAction::class
            ),
            'ADD_INCIDENT_NOTE' => new ActionDefinition(
                'ADD_INCIDENT_NOTE', 'Append a case note to the incident.', 'LOW', false,
                ['note'], 10, 0, AddIncidentNoteAction::class
            ),
            'REQUEST_APPROVAL' => new ActionDefinition(
                'REQUEST_APPROVAL', 'Pause execution and request human analyst approval.', 'MEDIUM', true,
                ['reason', 'required_tier'], 0, 0, RequestApprovalAction::class
            ),
            'NOTIFY_ANALYST' => new ActionDefinition(
                'NOTIFY_ANALYST', 'Send a notification to the assigned analyst.', 'LOW', false,
                ['title', 'message'], 10, 1, NotifyAnalystAction::class
            ),
            'CREATE_EVIDENCE_RECORD' => new ActionDefinition(
                'CREATE_EVIDENCE_RECORD', 'Persist a forensic evidence record attached to the incident.', 'LOW', false,
                ['title', 'content', 'evidence_type'], 15, 0, CreateEvidenceRecordAction::class
            ),
        ];
    }

    /** @throws InvalidArgumentException on unknown action type */
    public function getHandler(string $actionType): PlaybookActionHandler {
        if (!$this->isAllowed($actionType)) {
            throw new InvalidArgumentException("Action type '{$actionType}' is not in the registered allowlist.");
        }
        $handlerClass = self::$allowlist[$actionType];
        return new $handlerClass($this->pdo);
    }

    public function getDefinition(string $actionType): ActionDefinition {
        self::initDefinitions();
        if (!isset(self::$definitions[$actionType])) {
            throw new InvalidArgumentException("Action type '{$actionType}' has no registered definition.");
        }
        return self::$definitions[$actionType];
    }

    public function isAllowed(string $actionType): bool {
        return array_key_exists($actionType, self::$allowlist);
    }

    public function getAllowedTypes(): array {
        return array_keys(self::$allowlist);
    }

    public function getAllDefinitions(): array {
        self::initDefinitions();
        return array_map(fn($d) => $d->toArray(), self::$definitions);
    }
}
