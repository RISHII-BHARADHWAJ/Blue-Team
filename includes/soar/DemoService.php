<?php
/** Explicit, attributed training sessions. Generic simulated ingestion remains evidence-only. */
declare(strict_types=1);
require_once __DIR__ . '/SiemSoarAlertPipeline.php';
require_once __DIR__ . '/playbooks/PlaybookEngine.php';
final class DemoService
{
    public function __construct(private PDO $pdo) {}

    private function author(int $userId): array
    {
        $stmt = $this->pdo->prepare('SELECT id, username, role FROM users WHERE id = ?');
        $stmt->execute([$userId]); $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$user || !SoarAuth::hasPermission(SoarAuth::resolveTier($user['role']), 'create_incidents')) {
            throw new DomainException('A named Tier 2 or higher account is required to start a demo.');
        }
        $user['tier'] = SoarAuth::resolveTier($user['role']);
        return $user;
    }

    /** A replay of the same user + request key returns the existing case. */
    public function create(int $userId, string $requestKey): array
    {
        if (!preg_match('/^[a-f0-9]{32}$/D', $requestKey)) throw new InvalidArgumentException('Invalid demo request key.');
        return $this->atomic(function () use ($userId, $requestKey) {
            $author = $this->author($userId);
            $engine = new DetectionEngine($this->pdo);
            // Same lock ordering as ingestion, including simultaneous starts/retries.
            $rules = $engine->lockRules();
            $stmt = $this->pdo->prepare('INSERT IGNORE INTO demo_sessions (created_by, request_key) VALUES (?, ?)');
            $stmt->execute([$userId, $requestKey]);
            $stmt = $this->pdo->prepare('SELECT * FROM demo_sessions WHERE created_by = ? AND request_key = ? FOR UPDATE');
            $stmt->execute([$userId, $requestKey]); $session = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($session['incident_id'] !== null) return $session;
            $rule = null;
            foreach ($rules as $candidate) if ($candidate['rule_key'] === 'auth_failures') $rule = $candidate;
            if (!$rule || !$rule['enabled']) throw new UnexpectedValueException('Enable the authentication-failure rule in Detections before starting this demo.');
            $count = (int)$rule['threshold_count'];
            if ($count < 1 || $count > 100) throw new UnexpectedValueException('The authentication threshold must be between 1 and 100.');
            $pipeline = new SiemSoarAlertPipeline($this->pdo);
            $source = 'demo:' . $session['id'] . ':' . $requestKey;
            $logs = []; $finding = null;
            for ($i = 1; $i <= $count; $i++) {
                $result = $pipeline->ingest([
                    'source'=>$source, 'source_type'=>'demo', 'source_event_id'=>(string)$i,
                    'source_ip'=>'192.0.2.55', 'severity'=>'LOW', 'category'=>'SSH',
                    'message'=>"Training authentication failure $i of $count; no real login attempted.",
                    'is_simulated'=>true, 'event_timestamp'=>gmdate('c'),
                    'metadata'=>['event_type'=>'authentication', 'outcome'=>'failure', 'demo_session_id'=>(int)$session['id']],
                ], $author['username']);
                if (empty($result['success']) || !empty($result['duplicate']) || empty($result['log_id'])) {
                    throw new RuntimeException('Demo event ingestion failed.');
                }
                $logs[] = (int)$result['log_id'];
                foreach ($result['detections'] as $f) if ($f['rule_key'] === 'auth_failures') $finding = $f;
            }
            if (!$finding) throw new UnexpectedValueException('No threshold finding was produced; the demo has been rolled back.');
            $manager = new IncidentManager($this->pdo);
            $incident = $manager->createIncident([
                'title'=>'[SIMULATED] Authentication failure investigation', 'is_simulated'=>true,
                'description'=>'Training case generated from explicitly simulated events. No real authentication attempt, compromise, or containment is asserted.',
                'severity'=>$finding['severity'], 'attack_category'=>'SSH', 'assigned_to'=>$userId,
            ], null, null, $author['username']);
            foreach ($logs as $logId) $manager->attachAlert((int)$incident['id'], $logId, 'SIMULATED_DEMO', $author['username']);
            $engine->linkIncident([$finding], (int)$incident['id']);
            $stmt = $this->pdo->prepare('UPDATE demo_sessions SET incident_id = ?, finding_id = ? WHERE id = ?');
            $stmt->execute([$incident['id'], $finding['id'], $session['id']]);
            return $this->find((int)$session['id']);
        });
    }

    /** One persisted preview run per demo. No user-selectable playbook or execution mode. */
    public function preview(int $sessionId, int $userId): array
    {
        return $this->atomic(function () use ($sessionId, $userId) {
            $author = $this->author($userId);
            $stmt = $this->pdo->prepare('SELECT * FROM demo_sessions WHERE id = ? FOR UPDATE');
            $stmt->execute([$sessionId]); $session = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$session || (int)$session['created_by'] !== $userId) throw new DomainException('Only the demo creator may start its preview.');
            if ($session['playbook_run_id'] !== null) return $session;
            $incident = (new IncidentRepository($this->pdo))->find((int)$session['incident_id']);
            if (!$incident || empty($incident['is_simulated'])) throw new DomainException('A simulated incident is required.');
            $playbookId = $this->pdo->query("SELECT id FROM playbooks WHERE playbook_name='simulated_investigation_v1' AND is_active=1")->fetchColumn();
            if (!$playbookId) throw new UnexpectedValueException('The demo playbook is unavailable.');
            $run = (new PlaybookEngine($this->pdo))->startRun((int)$playbookId, (int)$incident['id'], 'DRY_RUN', $author);
            $this->pdo->prepare('UPDATE demo_sessions SET playbook_run_id = ? WHERE id = ?')->execute([$run['id'], $sessionId]);
            return $this->find($sessionId);
        });
    }

    public function find(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT d.*, u.username AS creator FROM demo_sessions d JOIN users u ON u.id=d.created_by WHERE d.id=?');
        $stmt->execute([$id]); return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    private function atomic(callable $work): array
    {
        $own = !$this->pdo->inTransaction(); $sp = 'demo_' . bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction(); else $this->pdo->exec("SAVEPOINT $sp");
        try {
            $result = $work();
            if ($own) $this->pdo->commit(); else $this->pdo->exec("RELEASE SAVEPOINT $sp");
            return $result;
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();
                else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $sp"); $this->pdo->exec("RELEASE SAVEPOINT $sp"); }
            }
            throw $e;
        }
    }
}
