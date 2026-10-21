<?php
declare(strict_types=1);
require_once __DIR__ . '/../soar/SoarAuth.php';
final class DetectionRepository
{
    public function __construct(private PDO $pdo) {}
    public function rules(): array
    {
        return $this->pdo->query('SELECT * FROM detection_rules ORDER BY rule_key')->fetchAll(PDO::FETCH_ASSOC);
    }

    /** Identity is the verified session's numeric ID; recheck its current database role. */
    public function updateRule(string $key, array $input, int $userId): void
    {
        if (!in_array($key, ['auth_failures', 'source_ip_intel'], true)) throw new InvalidArgumentException('Unknown rule.');
        $threshold = filter_var($input['threshold_count'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>2, 'max_range'=>100]]);
        $window = filter_var($input['window_seconds'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>60, 'max_range'=>86400]]);
        $revision = filter_var($input['revision'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
        $severity = $input['severity'] ?? null;
        $enabled = $input['enabled'] ?? null;
        if (($key === 'auth_failures' && !$threshold) || !$window || !$revision
            || !in_array($severity, ['LOW','MEDIUM','HIGH','CRITICAL'], true)
            || !in_array($enabled, ['0', '1'], true)) {
            throw new InvalidArgumentException('Use a valid severity, enabled flag, revision, 2–100 failures, and 60–86400 seconds.');
        }
        $own = !$this->pdo->inTransaction(); $savepoint = 'rule_' . bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction(); else $this->pdo->exec("SAVEPOINT $savepoint");
        try {
            $stmt = $this->pdo->prepare('SELECT * FROM detection_rules WHERE rule_key = ? FOR UPDATE');
            $stmt->execute([$key]); $before = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$before || (int)$before['revision'] !== $revision) throw new DomainException('This rule changed. Reload and review the current settings before saving.');
            $stmt = $this->pdo->prepare('SELECT username, role FROM users WHERE id = ?');
            $stmt->execute([$userId]); $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user || !SoarAuth::hasPermission(SoarAuth::resolveTier($user['role']), 'admin_operations')) {
                throw new UnexpectedValueException('Only a current administrator can configure detection rules.');
            }
            $after = ['enabled'=>(int)$enabled, 'severity'=>$severity,
                'threshold_count'=>$key === 'auth_failures' ? $threshold : 1, 'window_seconds'=>$window, 'revision'=>$revision+1];
            $stmt = $this->pdo->prepare('UPDATE detection_rules SET enabled=?, severity=?, threshold_count=?,
                window_seconds=?, revision=?, updated_at=UTC_TIMESTAMP(), updated_by=? WHERE rule_key=?');
            $stmt->execute([...array_values($after), $user['username'], $key]);
            $stmt = $this->pdo->prepare("INSERT INTO audit_log (analyst, ip_address, action, target, result, details, user_agent)
                VALUES (?, ?, 'update_detection_rule', ?, 'success', ?, ?)");
            $stmt->execute([$user['username'], substr($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1', 0, 45), $key,
                json_encode(['before'=>$before, 'after'=>$after], JSON_THROW_ON_ERROR),
                substr($_SERVER['HTTP_USER_AGENT'] ?? 'ThreatPulse-Detections', 0, 500)]);
            if ($own) $this->pdo->commit(); else $this->pdo->exec("RELEASE SAVEPOINT $savepoint");
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();
                else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $savepoint"); $this->pdo->exec("RELEASE SAVEPOINT $savepoint"); }
            }
            throw $e;
        }
    }

    public function findings(string $kind, int $page): array
    {
        $where = $kind === 'all' ? '' : ' WHERE is_simulated = ' . ($kind === 'simulated' ? '1' : '0');
        $total = (int)$this->pdo->query('SELECT COUNT(*) FROM detection_findings' . $where)->fetchColumn();
        $pages = max(1, (int)ceil($total/25)); $page = max(1, min($page, $pages));
        $stmt = $this->pdo->prepare('SELECT id, rule_key, severity, summary, is_simulated, created_at, incident_id
            FROM detection_findings' . $where . ' ORDER BY id DESC LIMIT 25 OFFSET ?');
        $stmt->bindValue(1, ($page-1)*25, PDO::PARAM_INT); $stmt->execute();
        return ['rows'=>$stmt->fetchAll(PDO::FETCH_ASSOC), 'total'=>$total, 'page'=>$page, 'pages'=>$pages];
    }

    public function find(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM detection_findings WHERE id=?'); $stmt->execute([$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC); if (!$row) return null;
        $stmt = $this->pdo->prepare('SELECT e.id, e.log_id, e.source, e.source_event_id, e.event_timestamp, e.received_at
            FROM detection_finding_evidence f JOIN event_evidence e ON e.id=f.evidence_id
            WHERE f.finding_id=? ORDER BY e.id'); $stmt->execute([$id]);
        $row['evidence'] = $stmt->fetchAll(PDO::FETCH_ASSOC); return $row;
    }
}
