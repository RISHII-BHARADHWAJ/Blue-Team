<?php
/**
 * ThreatPulse SOAR - Approval Repository
 *
 * Dedicated data access layer for approval requests.
 * Uses strict prepared statements, parameterized queries, and atomic row-count checks.
 */

class ApprovalRepository {
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
    }

    /**
     * Retrieve an approval record by ID.
     */
    public function findById(int $id): ?array {
        if (!$this->pdo) {
            return null;
        }

        $stmt = $this->pdo->prepare("SELECT * FROM approval_requests WHERE id = ? LIMIT 1");
        $stmt->execute([$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return null;

        if (is_string($row['action_payload'])) {
            $row['action_payload'] = json_decode($row['action_payload'], true) ?? $row['action_payload'];
        }
        return $row;
    }

    /**
     * Retrieve detailed approval with incident and playbook run information joined.
     */
    public function findWithDetails(int $id): ?array {
        if (!$this->pdo) {
            return null;
        }

        $stmt = $this->pdo->prepare("
            SELECT 
                a.*,
                i.incident_number,
                i.title AS incident_title,
                i.severity AS incident_severity,
                i.priority AS incident_priority,
                i.status AS incident_status,
                i.risk_score AS incident_risk_score,
                i.attack_category,
                i.mitre_tactics,
                i.mitre_techniques,
                r.playbook_id,
                r.playbook_version,
                r.run_uuid,
                r.status AS run_status,
                r.current_step_order,
                p.playbook_name,
                p.display_name AS playbook_display_name,
                p.category AS playbook_category,
                u.username AS reviewer_username
            FROM approval_requests a
            LEFT JOIN incidents i ON a.incident_id = i.id
            LEFT JOIN playbook_runs r ON a.playbook_run_id = r.id
            LEFT JOIN playbooks p ON r.playbook_id = p.id
            LEFT JOIN users u ON a.reviewed_by = u.id
            WHERE a.id = ?
            LIMIT 1
        ");
        $stmt->execute([$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) return null;

        if (is_string($row['action_payload'])) {
            $row['action_payload'] = json_decode($row['action_payload'], true) ?? $row['action_payload'];
        }
        return $row;
    }

    /**
     * Query approval requests with dynamic filtering, sorting, and pagination.
     */
    public function listApprovals(array $filters = [], int $limit = 50, int $offset = 0): array {
        if (!$this->pdo) {
            return [];
        }

        // Automatic maintenance: mark any expired pending approvals
        $this->markExpired();

        $where = ['1=1'];
        $params = [];

        if (!empty($filters['status'])) {
            $where[] = 'a.status = ?';
            $params[] = strtoupper(trim($filters['status']));
        }
        if (!empty($filters['incident_id'])) {
            $where[] = 'a.incident_id = ?';
            $params[] = (int)$filters['incident_id'];
        }
        if (!empty($filters['priority'])) {
            $where[] = 'i.priority = ?';
            $params[] = strtoupper(trim($filters['priority']));
        }
        if (!empty($filters['created_after'])) {
            $where[] = 'a.requested_at >= ?';
            $params[] = $filters['created_after'];
        }
        if (!empty($filters['created_before'])) {
            $where[] = 'a.requested_at <= ?';
            $params[] = $filters['created_before'];
        }

        $whereSql = implode(' AND ', $where);
        $limitInt = max(1, min(100, $limit));
        $offsetInt = max(0, $offset);

        $sql = "
            SELECT 
                a.*,
                i.incident_number,
                i.title AS incident_title,
                i.severity AS incident_severity,
                i.priority AS incident_priority,
                i.risk_score AS incident_risk_score,
                p.display_name AS playbook_name,
                u.username AS reviewer_username
            FROM approval_requests a
            LEFT JOIN incidents i ON a.incident_id = i.id
            LEFT JOIN playbook_runs r ON a.playbook_run_id = r.id
            LEFT JOIN playbooks p ON r.playbook_id = p.id
            LEFT JOIN users u ON a.reviewed_by = u.id
            WHERE {$whereSql}
            ORDER BY a.requested_at DESC, a.id DESC
            LIMIT {$limitInt} OFFSET {$offsetInt}
        ";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as &$row) {
            if (is_string($row['action_payload'])) {
                $row['action_payload'] = json_decode($row['action_payload'], true) ?? $row['action_payload'];
            }
        }
        return $rows;
    }

    /**
     * Atomically consume an approval request with state machine and expiry validation.
     * Returns true ONLY if exactly 1 row was updated from PENDING to APPROVED/REJECTED.
     */
    public function consumeDecision(int $approvalId, string $decision, int $reviewerId, ?string $reason = null): bool {
        if (!$this->pdo) {
            return false;
        }

        $targetStatus = strtoupper($decision) === 'APPROVE' ? 'APPROVED' : 'REJECTED';

        $stmt = $this->pdo->prepare("
            UPDATE approval_requests
            SET 
                status = ?,
                reviewed_by = ?,
                reviewed_at = NOW(),
                decided_at = NOW(),
                rejection_reason = ?
            WHERE id = ? 
              AND status = 'PENDING' 
              AND expires_at > NOW()
        ");
        $stmt->execute([$targetStatus, $reviewerId, $reason, $approvalId]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Mark expired pending approvals automatically.
     */
    public function markExpired(): int {
        if (!$this->pdo) {
            return 0;
        }

        try {
            $stmt = $this->pdo->prepare("
                UPDATE approval_requests
                SET status = 'EXPIRED', decided_at = NOW()
                WHERE status = 'PENDING' AND expires_at <= NOW()
            ");
            $stmt->execute();
            return $stmt->rowCount();
        } catch (Throwable $e) {
            return 0;
        }
    }

    /**
     * Cancel all pending approvals for a cancelled/failed run.
     */
    public function cancelPendingForRun(int $runId, string $reason = 'Playbook run cancelled or failed'): int {
        if (!$this->pdo) {
            return 0;
        }

        $stmt = $this->pdo->prepare("
            UPDATE approval_requests
            SET status = 'CANCELLED', rejection_reason = ?, decided_at = NOW()
            WHERE playbook_run_id = ? AND status = 'PENDING'
        ");
        $stmt->execute([$reason, $runId]);
        return $stmt->rowCount();
    }
}
