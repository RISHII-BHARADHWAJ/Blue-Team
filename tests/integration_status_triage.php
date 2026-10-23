<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
SoarAuth::getContext($pdo);
$_SESSION = ['analyst'=>'status-ci-lead','role'=>'admin'];
function statusCheck(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: '.$message);
    echo "PASS: $message\n";
}
$manager = new IncidentManager($pdo); $repo = new IncidentRepository($pdo);
$pdo->beginTransaction();
try {
    $name = 'status-ci-'.bin2hex(random_bytes(6));
    $id = $repo->create(['incident_number'=>$name,'title'=>$name]);
    $updated = $manager->changeStatus($id,'OPEN','status-ci-lead','Start triage','NEW');
    statusCheck($updated['status'] === 'OPEN' && count($updated['timeline']) === 1, 'transition writes one status event');
    $audit = $pdo->prepare("SELECT details FROM audit_log WHERE action='change_incident_status' AND target=? ORDER BY id");
    $audit->execute([$name]); $audits = $audit->fetchAll(PDO::FETCH_COLUMN);
    $details = json_decode($audits[0],true);
    statusCheck(count($audits) === 1 && $details['old_status'] === 'NEW' && $details['new_status'] === 'OPEN' && $details['reason'] === 'Start triage', 'audit preserves prior and next status and reason');
    $pdo->prepare("UPDATE incidents SET updated_at='2001-01-01 00:00:00' WHERE id=?")->execute([$id]);
    $before = $manager->getIncident($id);
    $retry = $manager->changeStatus($id,'OPEN','retry','Different retry reason','NEW');
    $audit->execute([$name]);
    statusCheck($retry === $before && count($audit->fetchAll()) === 1, 'same-target retry preserves timestamp, original reason, timeline and audit');
    $conflict = false;
    try { $manager->changeStatus($id,'CLOSED','stale-page','Finish','NEW'); } catch (IncidentStatusConflict $e) { $conflict = true; }
    statusCheck($conflict && $manager->getIncident($id) === $before, 'stale status rejects a transition that would otherwise still be allowed');
    $invalid = false;
    try { $manager->changeStatus($id,'RESOLVED','lead','Skip investigation','OPEN'); } catch (InvalidStateTransitionException $e) { $invalid = true; }
    statusCheck($invalid && $manager->getIncident($id) === $before, 'state-machine restrictions still apply when expectation matches');
    $legacy = $manager->changeStatus($id,'INVESTIGATING','legacy-client','Review evidence');
    statusCheck($legacy['status'] === 'INVESTIGATING', 'four-argument clients retain their existing call contract');
    $before = $manager->getIncident($id);
    foreach (['incident_timeline','audit_log'] as $table) {
        $pdo->exec("CREATE TEMPORARY TABLE $table (unrelated INT)");
        $failed = false;
        try { $manager->changeStatus($id,'RESOLVED','failing-writer','Must roll back','INVESTIGATING'); } catch (Throwable $e) { $failed = true; }
        $pdo->exec("DROP TEMPORARY TABLE $table");
        statusCheck($failed && $pdo->inTransaction() && $manager->getIncident($id) === $before, 'failed '.$table.' write rolls back status, lifecycle timestamp and history without losing caller work');
    }
    $resolved = $manager->changeStatus($id,'RESOLVED','lead','Investigation complete','INVESTIGATING');
    statusCheck($resolved['status'] === 'RESOLVED' && $resolved['resolved_at'] !== null, 'resolution time is saved on successful transition');
    statusCheck($manager->changeStatus($id,'RESOLVED','retry',null,'INVESTIGATING') === $resolved, 'resolution replay retains its original lifecycle time');
    $_SESSION['role'] = 'analyst';
    $denied = false;
    try { $manager->changeStatus($id,'CLOSED','analyst','Close','RESOLVED'); } catch (DomainException $e) { $denied = true; }
    statusCheck($denied && $repo->find($id)['status'] === 'RESOLVED', 'ordinary analyst cannot close a case');
    $_SESSION['role'] = 'admin';
    $closed = $manager->changeStatus($id,'CLOSED','lead','Accepted resolution','RESOLVED');
    statusCheck($closed['closed_at'] !== null && $manager->changeStatus($id,'CLOSED','retry',null,'RESOLVED') === $closed, 'authorized closed-case replay changes nothing');
    $_SESSION['role'] = 'analyst'; $denied = false;
    try { $manager->changeStatus($id,'CLOSED','analyst',null,'RESOLVED'); } catch (DomainException $e) { $denied = true; }
    statusCheck($denied, 'closed-case retries do not bypass close permission');
    $_SESSION['role'] = 'admin';
    $sim = $repo->create(['incident_number'=>$name.'-sim','title'=>$name,'is_simulated'=>true]);
    $simulation = $manager->changeStatus($sim,'OPEN','trainer','Practice','NEW');
    statusCheck((int)$simulation['is_simulated'] === 1 && $simulation['status'] === 'OPEN', 'simulation classification is preserved');
    $pdo->rollBack();
    // Exercise rollback of an owned transaction independently of the borrowed transaction above.
    $ownedId = $repo->create(['incident_number'=>$name.'-owned','title'=>$name]);
    $before = $manager->getIncident($ownedId);
    $pdo->exec('CREATE TEMPORARY TABLE audit_log (unrelated INT)');
    $failed = false;
    try { $manager->changeStatus($ownedId,'OPEN','lead','Owned rollback','NEW'); } catch (Throwable $e) { $failed = true; }
    $pdo->exec('DROP TEMPORARY TABLE audit_log');
    statusCheck($failed && !$pdo->inTransaction() && $manager->getIncident($ownedId) === $before, 'owned audit failure rolls back all writes and closes its transaction');
    statusCheck($manager->changeStatus($ownedId,'OPEN','lead','Retry after failure','NEW')['status'] === 'OPEN' && !$pdo->inTransaction(), 'owned successful retry commits cleanly');
    echo "Status triage integration passed.\n";
} catch (Throwable $e) {
    foreach (['incident_timeline','audit_log'] as $table) $pdo->exec("DROP TEMPORARY TABLE IF EXISTS $table");
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR,$e->getMessage()."\n"); exit(1);
}
