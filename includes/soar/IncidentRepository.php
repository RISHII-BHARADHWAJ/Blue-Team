<?php
/**
 * ThreatPulse SOAR - Incident Repository
 * 
 * Data access abstraction for incidents, incident_alerts, and user references.
 * Encapsulates all SQL execution for the Incident subsystem.
 */

class IncidentRepository {
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
    }

    /**
     * Find an incident by integer ID.
     */
    public function find(int $id, bool $lockForUpdate = false): ?array {
        if (!$this->pdo) {
            return null;
        }

        $sql = "
            SELECT i.*, 
                   u_assign.username AS assigned_username,
                   u_lead.username AS lead_username
            FROM incidents i
            LEFT JOIN users u_assign ON i.assigned_to = u_assign.id
            LEFT JOIN users u_lead ON i.lead_analyst = u_lead.id
            WHERE i.id = ?
        ";

        if ($lockForUpdate) {
            $sql .= " FOR UPDATE";
        }

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$id]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Find an incident by incident_number (e.g. INC-2026-0001).
     */
    public function findByNumber(string $incidentNumber): ?array {
        if (!$this->pdo) {
            return null;
        }

        $stmt = $this->pdo->prepare("
            SELECT i.*, 
                   u_assign.username AS assigned_username,
                   u_lead.username AS lead_username
            FROM incidents i
            LEFT JOIN users u_assign ON i.assigned_to = u_assign.id
            LEFT JOIN users u_lead ON i.lead_analyst = u_lead.id
            WHERE i.incident_number = ?
        ");
        $stmt->execute([$incidentNumber]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Find all active incidents within a lookback time window for correlation matching.
     */
    public function findActiveIncidentsForCorrelation(string $lookbackSince, ?string $sourceIp = null): array {
        if (!$this->pdo) {
            return [];
        }

        // Active statuses: NEW, OPEN, INVESTIGATING, CONTAINED
        $sql = "
            SELECT DISTINCT i.* 
            FROM incidents i
            LEFT JOIN incident_alerts ia ON i.id = ia.incident_id
            LEFT JOIN logs l ON ia.log_id = l.id
            WHERE i.status IN ('NEW', 'OPEN', 'INVESTIGATING', 'CONTAINED')
              AND i.is_simulated = 0 AND i.created_at >= ?
        ";
        $params = [$lookbackSince];

        if ($sourceIp !== null) {
            $sql .= " AND (l.source_ip = ? OR i.title LIKE ?)";
            $params[] = $sourceIp;
            $params[] = "%{$sourceIp}%";
        }

        $sql .= " ORDER BY i.created_at DESC FOR UPDATE";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    /**
     * Check if a legacy SIEM log record is already attached to any incident.
     */
    public function isLogAttached(int $logId): ?array {
        if (!$this->pdo) {
            return null;
        }

        $stmt = $this->pdo->prepare("
            SELECT ia.incident_id, i.incident_number, i.status, i.severity 
            FROM incident_alerts ia
            JOIN incidents i ON ia.incident_id = i.id
            WHERE ia.log_id = ?
            LIMIT 1
        ");
        $stmt->execute([$logId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    /**
     * Insert a new incident record into the database.
     */
    public function create(array $data): int {
        if (!$this->pdo) {
            static $mockIncId = 100;
            return $mockIncId++;
        }

        $stmt = $this->pdo->prepare("
            INSERT INTO incidents (
                incident_number, title, description, severity, status, priority, risk_score,
                assigned_to, lead_analyst, attack_category, mitre_tactics, mitre_techniques,
                is_simulated, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
        ");

        $stmt->execute([
            $data['incident_number'],
            $data['title'],
            $data['description'] ?? null,
            $data['severity'] ?? 'MEDIUM',
            $data['status'] ?? 'NEW',
            $data['priority'] ?? 'P3',
            $data['risk_score'] ?? 0,
            $data['assigned_to'] ?? null,
            $data['lead_analyst'] ?? null,
            $data['attack_category'] ?? null,
            $data['mitre_tactics'] ?? null,
            $data['mitre_techniques'] ?? null,
            (int)!empty($data['is_simulated'])
        ]);

        return (int)$this->pdo->lastInsertId();
    }

    /**
     * Update an incident record.
     */
    public function update(int $id, array $data): bool {
        if (!$this->pdo) {
            return true;
        }

        $fields = [];
        $params = [];

        foreach ($data as $key => $val) {
            if ($key === 'id') continue;
            if ($key === 'is_simulated') throw new InvalidArgumentException('Incident simulation classification is immutable.');
            $fields[] = "`$key` = ?";
            $params[] = $val;
        }

        if (empty($fields)) {
            return true;
        }

        $params[] = $id;
        $sql = "UPDATE incidents SET " . implode(', ', $fields) . ", updated_at = NOW() WHERE id = ?";
        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute($params);
    }

    /**
     * Attach a SIEM log record to an incident in the incident_alerts junction.
     */
    public function assertNotSimulated(int $logId): void {
        if (!$this->pdo) return;
        require_once __DIR__ . '/../siem/EventEvidenceRepository.php';
        if (!(new EventEvidenceRepository($this->pdo))->available()) return;
        $stmt = $this->pdo->prepare('SELECT is_simulated FROM event_evidence WHERE log_id = ?');
        $stmt->execute([$logId]);
        if ((int)$stmt->fetchColumn() === 1) {
            throw new InvalidArgumentException('Simulated evidence cannot be attached to a real incident.');
        }
    }

    public function attachAlert(int $incidentId, int $logId, string $correlationRule = 'CORRELATION'): int {
        if (!$this->pdo) {
            static $mockJunctionId = 1;
            return $mockJunctionId++;
        }

        $incident = $this->find($incidentId);
        if (!$incident) throw new InvalidArgumentException('Incident not found.');
        if (!empty($incident['is_simulated'])) {
            $check = $this->pdo->prepare('SELECT is_simulated FROM event_evidence WHERE log_id = ?');
            $check->execute([$logId]);
            if ((int)$check->fetchColumn() !== 1) throw new InvalidArgumentException('Simulated cases require simulated evidence.');
        } else {
            $this->assertNotSimulated($logId);
        }
        $stmt = $this->pdo->prepare("
            INSERT INTO incident_alerts (incident_id, log_id, correlation_rule, added_at)
            VALUES (?, ?, ?, NOW())
            ON DUPLICATE KEY UPDATE correlation_rule = VALUES(correlation_rule)
        ");
        $stmt->execute([$incidentId, $logId, $correlationRule]);
        return (int)$this->pdo->lastInsertId();
    }

    /**
     * Fetch all associated SIEM alerts for an incident.
     */
    public function getAttachedAlerts(int $incidentId): array {
        if (!$this->pdo) {
            return [];
        }

        $stmt = $this->pdo->prepare("
            SELECT ia.id AS junction_id, ia.correlation_rule, ia.added_at AS attached_at,
                   l.id AS log_id, l.source_ip, l.severity, l.category, l.message, l.timestamp AS event_timestamp
            FROM incident_alerts ia
            JOIN logs l ON ia.log_id = l.id
            WHERE ia.incident_id = ?
            ORDER BY l.timestamp DESC
        ");
        $stmt->execute([$incidentId]);
        return $stmt->fetchAll();
    }

    /**
     * Fetch all IOCs linked to an incident.
     */
    public function getIncidentIocs(int $incidentId): array {
        if (!$this->pdo) {
            return [];
        }

        $stmt = $this->pdo->prepare("
            SELECT ii.id AS link_id, ii.role, ii.discovered_at,
                   i.id AS ioc_id, i.ioc_type, i.ioc_value, i.threat_type, i.reputation_score, i.confidence_score
            FROM incident_iocs ii
            JOIN iocs i ON ii.ioc_id = i.id
            WHERE ii.incident_id = ?
        ");
        $stmt->execute([$incidentId]);
        return $stmt->fetchAll();
    }

    /**
     * List incidents with flexible filtering and pagination.
     */
    public function listIncidents(array $filters = [], int $limit = 50, int $offset = 0): array {
        if (!$this->pdo) {
            return [];
        }

        $limit = max(1, min(200, $limit));
        $offset = max(0, $offset);

        [$whereSql, $params] = $this->incidentFilterSql($filters);
        // Only allowlisted expressions can enter ORDER BY.
        $order = match ($filters['sort'] ?? 'priority') {
            'newest' => 'i.created_at DESC, i.id DESC',
            'oldest' => 'i.created_at ASC, i.id ASC',
            'least_updated' => 'i.updated_at ASC, i.id ASC',
            default => "FIELD(i.priority, 'P1', 'P2', 'P3', 'P4'), i.created_at DESC, i.id DESC",
        };

        $sql = "
            SELECT i.*, 
                   u_assign.username AS assigned_username,
                   u_lead.username AS lead_username,
                   COUNT(ia.id) AS alert_count
            FROM incidents i
            LEFT JOIN users u_assign ON i.assigned_to = u_assign.id
            LEFT JOIN users u_lead ON i.lead_analyst = u_lead.id
            LEFT JOIN incident_alerts ia ON i.id = ia.incident_id
            WHERE $whereSql
            GROUP BY i.id
            ORDER BY $order
            LIMIT ? OFFSET ?
        ";

        $stmt = $this->pdo->prepare($sql);
        $paramIndex = 1;
        foreach ($params as $p) {
            $stmt->bindValue($paramIndex++, $p);
        }
        $stmt->bindValue($paramIndex++, $limit, PDO::PARAM_INT);
        $stmt->bindValue($paramIndex++, $offset, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Count total incidents matching filters.
     */
    public function countIncidents(array $filters = []): int {
        if (!$this->pdo) {
            return 0;
        }

        [$whereSql, $params] = $this->incidentFilterSql($filters);
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM incidents i WHERE $whereSql");
        $stmt->execute($params);
        return (int)$stmt->fetchColumn();
    }

    /** Shared predicates keep list pagination and counts aligned. */
    private function incidentFilterSql(array $filters): array {
        $kind = $filters['kind'] ?? 'observed';
        $where = $kind === 'all' ? ['1=1'] : ['i.is_simulated = ' . ($kind === 'simulated' ? '1' : '0')];
        $params = [];
        foreach (['status'=>'status', 'severity'=>'severity', 'priority'=>'priority', 'category'=>'attack_category'] as $key=>$column) {
            if (!empty($filters[$key])) {
                $where[] = "i.$column = ?";
                $params[] = $filters[$key];
            }
        }
        if (!empty($filters['assigned_to'])) {
            $where[] = 'i.assigned_to = ?';
            $params[] = (int)$filters['assigned_to'];
        }
        if (!empty($filters['unassigned'])) $where[] = 'i.assigned_to IS NULL';
        if (($filters['lifecycle'] ?? '') === 'active') $where[] = "i.status IN ('NEW','OPEN','INVESTIGATING','CONTAINED')";
        if (($filters['lifecycle'] ?? '') === 'finished') $where[] = "i.status IN ('RESOLVED','CLOSED')";
        foreach (['created_after'=>'>=', 'created_before'=>'<='] as $key=>$operator) {
            if (!empty($filters[$key])) {
                $where[] = "i.created_at $operator ?";
                $params[] = $filters[$key];
            }
        }
        if (isset($filters['q']) && $filters['q'] !== '') {
            // Escape LIKE metacharacters: user text is a literal substring.
            $term = '%' . strtr($filters['q'], ['!'=>'!!', '%'=>'!%', '_'=>'!_']) . '%';
            $where[] = "(i.incident_number LIKE ? ESCAPE '!' OR i.title LIKE ? ESCAPE '!')";
            array_push($params, $term, $term);
        }
        $days = (int)($filters['stale_days'] ?? 0);
        if (in_array($days, [1,3,7,30], true)) {
            $where[] = 'i.updated_at <= DATE_SUB(NOW(), INTERVAL ? DAY)';
            $params[] = $days;
        }
        return [implode(' AND ', $where), $params];
    }

    /**
     * Look up user by ID.
     */
    public function findUserById(int $userId): ?array {
        if (!$this->pdo) {
            return null;
        }

        $stmt = $this->pdo->prepare("SELECT id, username, email, role FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }
}
