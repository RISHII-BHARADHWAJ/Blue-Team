<?php
/**
 * ThreatPulse SOAR - Playbook Repository
 *
 * Database access layer for playbooks, steps, runs, approvals, and step results.
 * All queries use parameterized statements — no dynamic SQL from playbook data.
 */
class PlaybookRepository {
    private ?PDO $pdo;

    public function __construct(?PDO $pdo = null) {
        $this->pdo = $pdo;
    }

    // ---------- Playbooks ----------------------------------------------------

    public function findPlaybook(int $id): ?array {
        if (!$this->pdo) return null;
        $stmt = $this->pdo->prepare("SELECT * FROM playbooks WHERE id = ? LIMIT 1");
        $stmt->execute([$id]);
        return $stmt->fetch() ?: null;
    }

    public function findActivePlaybooks(array $filters = [], int $limit = 50): array {
        if (!$this->pdo) return [];
        $where = ['is_active = 1'];
        $params = [];
        if (!empty($filters['category'])) {
            $where[] = 'category = ?';
            $params[] = $filters['category'];
        }
        $sql = "SELECT * FROM playbooks WHERE " . implode(' AND ', $where)
             . " ORDER BY id ASC LIMIT " . (int)$limit;
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    public function createPlaybook(array $data, int $createdBy): int {
        if (!$this->pdo) return 0;
        $stmt = $this->pdo->prepare("
            INSERT INTO playbooks
                (playbook_name, display_name, description, category, trigger_type,
                 requires_approval, min_approval_tier, is_active, version, created_by)
            VALUES (?,?,?,?,?,?,?,?,1,?)
        ");
        $stmt->execute([
            $data['playbook_name'], $data['display_name'],
            $data['description'] ?? null, strtoupper($data['category']),
            strtoupper($data['trigger_type'] ?? 'MANUAL'),
            (int)($data['requires_approval'] ?? 0),
            strtoupper($data['min_approval_tier'] ?? 'LEAD'),
            (int)($data['is_active'] ?? 1),
            $createdBy,
        ]);
        return (int)$this->pdo->lastInsertId();
    }

    // ---------- Steps --------------------------------------------------------

    public function getSteps(int $playbookId): array {
        if (!$this->pdo) return [];
        $stmt = $this->pdo->prepare("
            SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_order ASC
        ");
        $stmt->execute([$playbookId]);
        return $stmt->fetchAll();
    }

    public function createStep(int $playbookId, array $step): int {
        if (!$this->pdo) return 0;
        $params = is_array($step['action_parameters'] ?? null)
            ? json_encode($step['action_parameters'], JSON_UNESCAPED_SLASHES)
            : ($step['action_parameters'] ?? null);

        $stmt = $this->pdo->prepare("
            INSERT INTO playbook_steps
                (playbook_id, step_order, step_name, action_type, action_parameters,
                 on_success_step, on_failure_step, timeout_seconds)
            VALUES (?,?,?,?,?,?,?,?)
        ");
        $stmt->execute([
            $playbookId,
            (int)$step['step_order'],
            $step['step_name'],
            strtoupper($step['action_type']),
            $params,
            $step['on_success_step'] ?? null,
            $step['on_failure_step'] ?? null,
            (int)($step['timeout_seconds'] ?? 60),
        ]);
        return (int)$this->pdo->lastInsertId();
    }

    // ---------- Runs ---------------------------------------------------------

    public function findRun(int $runId): ?array {
        if (!$this->pdo) return null;
        $stmt = $this->pdo->prepare("SELECT * FROM playbook_runs WHERE id = ? LIMIT 1");
        $stmt->execute([$runId]);
        $row = $stmt->fetch();
        if (!$row) return null;
        if (is_string($row['execution_context'])) {
            $row['execution_context'] = json_decode($row['execution_context'], true);
        }
        return $row;
    }

    public function findRunByUuid(string $uuid): ?array {
        if (!$this->pdo) return null;
        $stmt = $this->pdo->prepare("SELECT * FROM playbook_runs WHERE run_uuid = ? LIMIT 1");
        $stmt->execute([$uuid]);
        return $stmt->fetch() ?: null;
    }

    public function createRun(int $playbookId, ?int $incidentId, string $triggeredBy, ?int $analystId, string $uuid, array $execContext = [], ?int $playbookVersion = null): int {
        if (!$this->pdo) return 0;

        // Resolve immutable playbook version if not supplied
        if ($playbookVersion === null) {
            $pb = $this->findPlaybook($playbookId);
            $playbookVersion = (int)($pb['version'] ?? 1);
        }

        $stmt = $this->pdo->prepare("
            INSERT INTO playbook_runs
                (run_uuid, playbook_id, playbook_version, incident_id, triggered_by, analyst_id, status, execution_context)
            VALUES (?,?,?,?,?,?,'PENDING',?)
        ");
        $stmt->execute([
            $uuid, $playbookId, $playbookVersion, $incidentId,
            in_array($triggeredBy, ['AUTOMATION','ANALYST'], true) ? $triggeredBy : 'ANALYST',
            $analystId,
            json_encode($execContext, JSON_UNESCAPED_SLASHES)
        ]);
        return (int)$this->pdo->lastInsertId();
    }

    /**
     * Find a playbook definition by its immutable version.
     */
    public function findPlaybookByNameAndVersion(string $name, int $version): ?array {
        if (!$this->pdo) return null;
        $stmt = $this->pdo->prepare("SELECT * FROM playbooks WHERE playbook_name = ? AND version = ? LIMIT 1");
        $stmt->execute([$name, $version]);
        return $stmt->fetch() ?: null;
    }

    /**
     * Find the currently active version of a playbook by name.
     */
    public function findActivePlaybookByName(string $name): ?array {
        if (!$this->pdo) return null;
        $stmt = $this->pdo->prepare("SELECT * FROM playbooks WHERE playbook_name = ? AND is_active = 1 ORDER BY version DESC LIMIT 1");
        $stmt->execute([$name]);
        return $stmt->fetch() ?: null;
    }

    public function updateRunStatus(int $runId, string $status, ?string $error = null, ?int $currentStep = null): void {
        if (!$this->pdo) return;
        $validStatuses = ['PENDING','RUNNING','WAITING_APPROVAL','COMPLETED','FAILED','CANCELLED'];
        if (!in_array($status, $validStatuses, true)) {
            throw new InvalidArgumentException("Invalid run status: {$status}");
        }
        $completed = in_array($status, ['COMPLETED','FAILED','CANCELLED']) ? 'NOW()' : 'NULL';
        $params = [$status];
        $stepSql = '';
        if ($currentStep !== null) {
            $stepSql = ', current_step_order = ?';
            $params[] = $currentStep;
        }
        if ($error !== null) {
            $params[] = substr($error, 0, 1000);
            $params[] = $runId;
            $this->pdo->prepare("UPDATE playbook_runs SET status = ?, error_message = ?{$stepSql}, completed_at = {$completed} WHERE id = ?")->execute($params);
        } else {
            $params[] = $runId;
            $this->pdo->prepare("UPDATE playbook_runs SET status = ?{$stepSql}, completed_at = {$completed} WHERE id = ?")->execute($params);
        }
    }

    // ---------- Step Results -------------------------------------------------

    public function logStepResult(array $data): int {
        if (!$this->pdo) return 0;
        $stmt = $this->pdo->prepare("
            INSERT INTO playbook_step_results
                (playbook_run_id, step_id, step_order, action_type, attempt_number,
                 status, started_at, completed_at, output, error_message, is_dry_run)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ");
        $stmt->execute([
            $data['playbook_run_id'],
            $data['step_id'],
            $data['step_order'],
            $data['action_type'],
            $data['attempt_number'] ?? 1,
            $data['status'],
            $data['started_at'],
            $data['completed_at'] ?? null,
            isset($data['output']) ? json_encode($data['output'], JSON_UNESCAPED_SLASHES) : null,
            $data['error_message'] ?? null,
            (int)($data['is_dry_run'] ?? 0),
        ]);
        return (int)$this->pdo->lastInsertId();
    }

    public function getStepResults(int $runId): array {
        if (!$this->pdo) return [];
        $stmt = $this->pdo->prepare("SELECT * FROM playbook_step_results WHERE playbook_run_id = ? ORDER BY step_order ASC, attempt_number ASC");
        $stmt->execute([$runId]);
        return $stmt->fetchAll();
    }

    /**
     * Idempotency check: return an existing SUCCESS result for this run+step, or null.
     * Called before executing a step to prevent double-execution on resume.
     */
    public function findSuccessfulStepResult(int $runId, int $stepOrder): ?array {
        if (!$this->pdo) return null;
        $stmt = $this->pdo->prepare("
            SELECT * FROM playbook_step_results
            WHERE playbook_run_id = ? AND step_order = ? AND status = 'SUCCESS'
            ORDER BY attempt_number DESC LIMIT 1
        ");
        $stmt->execute([$runId, $stepOrder]);
        return $stmt->fetch() ?: null;
    }

    /**
     * Return the most recent result for a run+step regardless of status.
     * Used to determine the current attempt number for retries.
     */
    public function findLatestStepResult(int $runId, int $stepOrder): ?array {
        if (!$this->pdo) return null;
        $stmt = $this->pdo->prepare("
            SELECT * FROM playbook_step_results
            WHERE playbook_run_id = ? AND step_order = ?
            ORDER BY attempt_number DESC LIMIT 1
        ");
        $stmt->execute([$runId, $stepOrder]);
        return $stmt->fetch() ?: null;
    }

    /**
     * Advance the execution cursor on a run to the next step order.
     * Called immediately after a step completes (success or failure-branch).
     */
    public function updateCursor(int $runId, int $nextStepOrder): void {
        if (!$this->pdo) return;
        $stmt = $this->pdo->prepare("
            UPDATE playbook_runs SET current_step_order = ? WHERE id = ?
        ");
        $stmt->execute([$nextStepOrder, $runId]);
    }

    // ---------- Approvals ----------------------------------------------------

    public function createApprovalRequest(array $data): int {
        if (!$this->pdo) return 0;
        $payload = is_array($data['action_payload']) ? json_encode($data['action_payload'], JSON_UNESCAPED_SLASHES) : $data['action_payload'];
        $hash    = hash('sha256', $payload);
        $stmt = $this->pdo->prepare("
            INSERT INTO approval_requests
                (playbook_run_id, incident_id, action_name, action_description, action_payload, payload_hash, required_tier, expires_at)
            VALUES (?,?,?,?,?,?,?,?)
        ");
        $stmt->execute([
            $data['playbook_run_id'],
            $data['incident_id'],
            substr($data['action_name'], 0, 100),
            $data['action_description'],
            $payload,
            $hash,
            strtoupper($data['required_tier'] ?? 'LEAD'),
            $data['expires_at'] ?? date('Y-m-d H:i:s', strtotime('+24 hours')),
        ]);
        return (int)$this->pdo->lastInsertId();
    }

    public function findPendingApproval(int $runId): ?array {
        if (!$this->pdo) return null;
        $stmt = $this->pdo->prepare("
            SELECT * FROM approval_requests
            WHERE playbook_run_id = ? AND status = 'PENDING' AND expires_at > NOW()
            ORDER BY requested_at DESC LIMIT 1
        ");
        $stmt->execute([$runId]);
        return $stmt->fetch() ?: null;
    }

    public function consumeApproval(int $approvalId, int $reviewerId, string $decision, ?string $reason = null): bool {
        if (!$this->pdo) return false;
        $status = in_array(strtoupper($decision), ['APPROVED','REJECTED'], true) ? strtoupper($decision) : 'REJECTED';
        $stmt = $this->pdo->prepare("
            UPDATE approval_requests
            SET status = ?, reviewed_by = ?, reviewed_at = NOW(), rejection_reason = ?
            WHERE id = ? AND status = 'PENDING' AND expires_at > NOW()
        ");
        $stmt->execute([$status, $reviewerId, $reason, $approvalId]);
        return $stmt->rowCount() === 1;
    }

    /**
     * Load an approval request by its primary key (used for hash verification on resume).
     */
    public function findApprovalById(int $approvalId): ?array {
        if (!$this->pdo) return null;
        $stmt = $this->pdo->prepare("SELECT * FROM approval_requests WHERE id = ? LIMIT 1");
        $stmt->execute([$approvalId]);
        return $stmt->fetch() ?: null;
    }
}
