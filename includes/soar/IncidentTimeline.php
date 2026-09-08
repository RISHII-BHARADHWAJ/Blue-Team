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
}
