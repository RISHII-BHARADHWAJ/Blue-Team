<?php
/** Incident-scoped run history and attributed, retry-safe previews. */
declare(strict_types=1);
require_once __DIR__ . '/PlaybookEngine.php';
final class PlaybookWorkspace
{
    private PlaybookRepository $repo;
    public function __construct(private PDO $pdo) { $this->repo = new PlaybookRepository($pdo); }

    /** Only this fixed DRY_RUN path is exposed by the workspace. */
    public function preview(int $incidentId, int $playbookId, int $version, int $userId, string $requestKey): array
    {
        if ($incidentId < 1 || $playbookId < 1 || $version < 1 || !preg_match('/^[a-f0-9]{32}$/D', $requestKey)) {
            throw new InvalidArgumentException('Valid incident, playbook, version and request key are required.');
        }
        $own = !$this->pdo->inTransaction(); $sp = 'preview_' . bin2hex(random_bytes(8));
        if ($own) $this->pdo->beginTransaction(); else $this->pdo->exec("SAVEPOINT $sp");
        try {
            $stmt = $this->pdo->prepare('SELECT id, username, role FROM users WHERE id = ?');
            $stmt->execute([$userId]); $author = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$author || !SoarAuth::hasPermission(SoarAuth::resolveTier($author['role']), 'view_incidents')) {
                throw new DomainException('Sign in with a named analyst account to preview a playbook.');
            }
            // Lock the parent case before request insertion, matching engine lock order.
            $incident = (new IncidentRepository($this->pdo))->find($incidentId, true);
            if (!$incident) throw new OutOfBoundsException('Incident not found.');
            $stmt = $this->pdo->prepare('SELECT * FROM playbooks WHERE id = ? FOR UPDATE');
            $stmt->execute([$playbookId]); $playbook = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$playbook) throw new OutOfBoundsException('Playbook not found.');
            $stmt = $this->pdo->prepare('INSERT IGNORE INTO playbook_preview_requests
                (user_id, request_key, incident_id, playbook_id, playbook_version) VALUES (?, ?, ?, ?, ?)');
            $stmt->execute([$userId, $requestKey, $incidentId, $playbookId, $version]);
            $stmt = $this->pdo->prepare('SELECT * FROM playbook_preview_requests WHERE user_id = ? AND request_key = ? FOR UPDATE');
            $stmt->execute([$userId, $requestKey]); $request = $stmt->fetch(PDO::FETCH_ASSOC);
            if ((int)$request['incident_id'] !== $incidentId || (int)$request['playbook_id'] !== $playbookId || (int)$request['playbook_version'] !== $version) {
                throw new UnexpectedValueException('This request key was used for another preview. Reload the page before starting a new one.');
            }
            if ($request['run_id'] !== null) {
                // A waiting retry may have an older REPEATABLE READ snapshot.
                // Match the request's current locking read when loading its run.
                $run = $this->repo->findRun((int)$request['run_id'], true);
            } else {
                if (!$playbook['is_active'] || (int)$playbook['version'] !== $version) {
                    throw new UnexpectedValueException('The playbook changed or was disabled. Reload and inspect its current definition.');
                }
                $steps = $this->repo->getSteps($playbookId);
                foreach ($steps as $step) {
                    if ((int)$step['step_order'] < 1 || !is_array(json_decode($step['action_parameters'] ?? '{}', true))) {
                        throw new UnexpectedValueException('Step order and parameters must be valid before previewing.');
                    }
                }
                if (!$steps || (new PlaybookValidator($this->pdo))->validate($playbook, $steps)) {
                    throw new UnexpectedValueException('This playbook has no steps or has an invalid definition. Ask an administrator to review it.');
                }
                $run = (new PlaybookEngine($this->pdo))->startRun($playbookId, $incidentId, 'DRY_RUN', [
                    'id'=>$userId, 'username'=>$author['username'], 'tier'=>SoarAuth::resolveTier($author['role']),
                ]);
                $context = $run['execution_context'];
                // Preserve what was previewed even if a definition is changed later.
                $context['definition_snapshot'] = ['playbook'=>$playbook, 'steps'=>$steps];
                $this->pdo->prepare('UPDATE playbook_runs SET execution_context = ? WHERE id = ?')
                    ->execute([json_encode($context, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), $run['id']]);
                $this->pdo->prepare('UPDATE playbook_preview_requests SET run_id = ? WHERE id = ?')->execute([$run['id'], $request['id']]);
                $run = $this->repo->findRun((int)$run['id']);
            }
            if (!$run) throw new RuntimeException('The saved preview run could not be loaded.');
            if ($own) $this->pdo->commit(); else $this->pdo->exec("RELEASE SAVEPOINT $sp");
            return $run;
        } catch (Throwable $e) {
            if ($this->pdo->inTransaction()) {
                if ($own) $this->pdo->rollBack();
                else { $this->pdo->exec("ROLLBACK TO SAVEPOINT $sp"); $this->pdo->exec("RELEASE SAVEPOINT $sp"); }
            }
            throw $e;
        }
    }

    public function read(int $incidentId, int $page = 1, ?int $runId = null, ?int $playbookId = null, int $catalogPage = 1): array
    {
        $incident = (new IncidentRepository($this->pdo))->find($incidentId);
        if (!$incident) throw new OutOfBoundsException('Incident not found.');
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM playbook_runs WHERE incident_id = ?');
        $stmt->execute([$incidentId]); $total = (int)$stmt->fetchColumn();
        $pages = max(1, (int)ceil($total / 25)); $page = max(1, min($page, $pages));
        $stmt = $this->pdo->prepare('SELECT r.*, p.display_name, u.username AS analyst_name FROM playbook_runs r
            JOIN playbooks p ON p.id = r.playbook_id LEFT JOIN users u ON u.id = r.analyst_id
            WHERE r.incident_id = ? ORDER BY r.id DESC LIMIT 25 OFFSET ?');
        $stmt->bindValue(1, $incidentId, PDO::PARAM_INT); $stmt->bindValue(2, ($page - 1) * 25, PDO::PARAM_INT); $stmt->execute();
        $runs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($runs as &$row) $row['execution_context'] = json_decode($row['execution_context'] ?? '{}', true) ?: [];
        unset($row);
        $run = null; $results = []; $approval = null;
        if ($runId !== null) {
            $run = $this->repo->findRun($runId);
            if (!$run || (int)$run['incident_id'] !== $incidentId) throw new OutOfBoundsException('Run not found for this incident.');
            $results = $this->repo->getStepResults($runId);
            $approval = $this->repo->findPendingApproval($runId);
        }
        $catalogTotal = (int)$this->pdo->query('SELECT COUNT(*) FROM playbooks WHERE is_active = 1')->fetchColumn();
        $catalogPages = max(1, (int)ceil($catalogTotal / 10)); $catalogPage = max(1, min($catalogPage, $catalogPages));
        $stmt = $this->pdo->prepare('SELECT * FROM playbooks WHERE is_active = 1 ORDER BY id LIMIT 10 OFFSET ?');
        $stmt->bindValue(1, ($catalogPage - 1) * 10, PDO::PARAM_INT); $stmt->execute(); $catalog = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $definition = null; $steps = [];
        if ($playbookId !== null) {
            $definition = $this->repo->findPlaybook($playbookId);
            if (!$definition || !$definition['is_active']) throw new OutOfBoundsException('Active playbook not found.');
            $steps = $this->repo->getSteps($playbookId);
        }
        return compact('incident', 'runs', 'run', 'results', 'approval', 'catalog', 'definition', 'steps') + [
            'pagination'=>['page'=>$page, 'pages'=>$pages, 'total'=>$total],
            'catalog_pagination'=>['page'=>$catalogPage, 'pages'=>$catalogPages, 'total'=>$catalogTotal],
        ];
    }
}
