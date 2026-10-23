<?php
/**
 * ThreatPulse SOAR - Incident Timeline Service
 * 
 * Manages chronological, append-only incident milestone tracking:
 * - ALERT_ADDED
 * - STATUS_CHANGE
 * - SEVERITY_CHANGE
 * - PLAYBOOK_STARTED
 * - PLAYBOOK_STEP
 * - APPROVAL_REQUESTED
 * - APPROVAL_GRANTED
 * - APPROVAL_REJECTED
 * - ACTION_EXECUTED
 * - EVIDENCE_ATTACHED
 * - NOTE_ADDED
 * 
 * Safety: strictly INSERT-only; no UPDATE or DELETE operations.
 */

class IncidentTimeline {
    private ?PDO $pdo;

    public const EVENT_TYPES = [
        'ALERT_ADDED', 'STATUS_CHANGE', 'SEVERITY_CHANGE', 'PLAYBOOK_STARTED',
        'PLAYBOOK_STEP', 'APPROVAL_REQUESTED', 'APPROVAL_GRANTED', 'APPROVAL_REJECTED',
        'ACTION_EXECUTED', 'EVIDENCE_ATTACHED', 'NOTE_ADDED',
    ];
    public const ACTOR_TYPES = ['SYSTEM', 'ANALYST', 'PLAYBOOK'];
    public const PAGE_SIZE = 25;

    public const ACTOR_SYSTEM   = 'SYSTEM';
    public const ACTOR_ANALYST  = 'ANALYST';
    public const ACTOR_PLAYBOOK = 'PLAYBOOK';

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
    }

    /**
     * Append a new chronological event to an incident timeline.
     * 
     * @param int $incidentId Target incident ID
     * @param string $eventType Standardized event type
     * @param string $actorType SYSTEM | ANALYST | PLAYBOOK
     * @param string $actorName Name of analyst, playbook, or engine component
     * @param string $summary Brief summary description
     * @param ?array $details Contextual structured details
     * @return int Inserted timeline event ID (or simulated ID if in-memory)
     */
    public function addEvent(
        int $incidentId,
        string $eventType,
        string $actorType,
        string $actorName,
        string $summary,
        ?array $details = null
    ): int {
        if (!$this->pdo) {
            static $mockTimelineId = 1;
            return $mockTimelineId++;
        }

        $detailsJson = $details !== null ? json_encode($details, JSON_UNESCAPED_SLASHES) : null;

        $stmt = $this->pdo->prepare("
            INSERT INTO incident_timeline (
                incident_id, event_type, actor_type, actor_name, summary, details, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $incidentId,
            $eventType,
            $actorType,
            substr($actorName, 0, 100),
            substr($summary, 0, 255),
            $detailsJson
        ]);

        return (int)$this->pdo->lastInsertId();
    }

    /**
     * Retrieve all chronological timeline events for an incident.
     */
    public function getEvents(int $incidentId): array {
        if (!$this->pdo) {
            return [];
        }

        $stmt = $this->pdo->prepare("
            SELECT id, incident_id, event_type, actor_type, actor_name, summary, details, created_at 
            FROM incident_timeline 
            WHERE incident_id = ? 
            ORDER BY created_at ASC, id ASC
        ");
        $stmt->execute([$incidentId]);
        $rows = $stmt->fetchAll();

        foreach ($rows as &$row) {
            if (!empty($row['details']) && is_string($row['details'])) {
                $row['details'] = json_decode($row['details'], true) ?: $row['details'];
            }
        }

        return $rows;
    }

    /** Recent summary-only preview, newest first; the legacy full-history API is unchanged. */
    public function getRecentEvents(int $incidentId, int $limit = 20): array {
        if (!$this->pdo) return [];
        $limit = max(1, min(100, $limit));
        $stmt = $this->pdo->prepare("SELECT id, incident_id, event_type, actor_type, actor_name, summary, created_at
            FROM incident_timeline WHERE incident_id = ? ORDER BY created_at DESC, id DESC LIMIT $limit");
        $stmt->execute([$incidentId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /** Bounded, case-scoped history. Details payloads are neither fetched nor searched. */
    public function search(int $incidentId, array $input = [], int $page = 1): array {
        $filters = [];
        foreach (['q', 'event_type', 'actor_type', 'sort'] as $key) {
            $value = $input[$key] ?? ($key === 'sort' ? 'newest' : '');
            if (!is_string($value) || strlen($value) > 200 || !preg_match('//u', $value)) {
                throw new InvalidArgumentException('Timeline filters must be valid UTF-8 text of at most 200 bytes.');
            }
            $filters[$key] = trim($value);
        }
        foreach (['event_type'=>self::EVENT_TYPES, 'actor_type'=>self::ACTOR_TYPES, 'sort'=>['newest','oldest']] as $key=>$allowed) {
            if (!in_array($filters[$key], $key === 'sort' ? $allowed : array_merge([''], $allowed), true)) {
                throw new InvalidArgumentException('Select a valid timeline event type, actor type and sort order.');
            }
        }
        if ($incidentId < 1) throw new InvalidArgumentException('Select a valid incident.');
        $where = ['incident_id = ?'];
        $params = [$incidentId];
        foreach (['event_type', 'actor_type'] as $key) {
            if ($filters[$key] !== '') { $where[] = "$key = ?"; $params[] = $filters[$key]; }
        }
        if ($filters['q'] !== '') {
            $needle = '%'.strtr($filters['q'], ['!'=>'!!', '%'=>'!%', '_'=>'!_']).'%';
            $where[] = "(summary LIKE ? ESCAPE '!' OR actor_name LIKE ? ESCAPE '!')";
            $params[] = $needle; $params[] = $needle;
        }
        $predicate = implode(' AND ', $where);
        $direction = $filters['sort'] === 'oldest' ? 'ASC' : 'DESC';
        $result = ['filters'=>$filters, 'rows'=>[], 'total'=>0, 'page'=>1, 'pages'=>1];
        if (!$this->pdo) return $result;
        // Keep count and page consistent within one request. Never commit a caller's transaction.
        $own = !$this->pdo->inTransaction();
        if ($own) {
            $this->pdo->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
            $this->pdo->beginTransaction();
        }
        try {
            $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM incident_timeline WHERE $predicate");
            $stmt->execute($params);
            $result['total'] = (int)$stmt->fetchColumn();
            $result['pages'] = max(1, (int)ceil($result['total'] / self::PAGE_SIZE));
            $result['page'] = max(1, min($page, $result['pages']));
            $offset = ($result['page'] - 1) * self::PAGE_SIZE;
            $limit = self::PAGE_SIZE;
            $stmt = $this->pdo->prepare("SELECT id, incident_id, event_type, actor_type, actor_name, summary, created_at
                FROM incident_timeline WHERE $predicate ORDER BY created_at $direction, id $direction LIMIT $limit OFFSET $offset");
            $stmt->execute($params);
            $result['rows'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($own) $this->pdo->commit();
            return $result;
        } catch (Throwable $e) {
            if ($own && $this->pdo->inTransaction()) $this->pdo->rollBack();
            throw $e;
        }
    }

}
