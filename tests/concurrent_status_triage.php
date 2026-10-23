<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
SoarAuth::getContext($pdo);
$_SESSION = ['analyst'=>'concurrent-status-lead','role'=>'admin'];
if (($argv[1] ?? '') === 'worker') {
    try {
        $pdo->beginTransaction();
        $pdo->query('SELECT COUNT(*) FROM incidents')->fetchColumn();
        echo "READY\n"; fflush(STDOUT);
        $row = (new IncidentManager($pdo))->changeStatus((int)$argv[2],$argv[3],'concurrent-status-lead','Concurrent triage','NEW');
        $pdo->commit(); echo $row['status']; exit(0);
    } catch (IncidentStatusConflict $e) {
        if ($pdo->inTransaction()) $pdo->rollBack(); echo 'CONFLICT'; exit(0);
    } catch (Throwable $e) { fwrite(STDERR,$e->getMessage()); exit(1); }
}
try {
    $name = 'status-race-'.bin2hex(random_bytes(5)); $repo = new IncidentRepository($pdo);
    foreach (['retry','conflict'] as $mode) {
        $number = $name.'-'.$mode;
        $id = $repo->create(['incident_number'=>$number,'title'=>$number]);
        $pdo->beginTransaction(); $repo->find($id,true);
        $workers = []; $targets = $mode === 'retry' ? ['OPEN','OPEN','OPEN'] : ['OPEN','CLOSED'];
        foreach ($targets as $target) {
            $p = proc_open([PHP_BINARY,__FILE__,'worker',(string)$id,$target], [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
            if (!is_resource($p)) throw new RuntimeException('Could not start worker');
            fclose($pipes[0]); $workers[] = [$p,$pipes];
        }
        foreach ($workers as [$p,$pipes]) {
            if (trim((string)fgets($pipes[1])) !== 'READY') throw new RuntimeException('Worker did not establish snapshot');
        }
        $pdo->commit(); $results = [];
        foreach ($workers as [$p,$pipes]) {
            $out = trim(stream_get_contents($pipes[1])); $err = stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            if (proc_close($p) !== 0) throw new RuntimeException($err);
            $results[] = $out;
        }
        $current = $repo->find($id);
        $stmt = $pdo->prepare('SELECT details FROM incident_timeline WHERE incident_id=?'); $stmt->execute([$id]); $events = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $stmt = $pdo->prepare("SELECT details FROM audit_log WHERE target=? AND action='change_incident_status'"); $stmt->execute([$number]); $audits = $stmt->fetchAll(PDO::FETCH_COLUMN);
        if (count($events) !== 1 || count($audits) !== 1 || json_decode($events[0],true)['new_status'] !== $current['status'] || json_decode($audits[0],true)['new_status'] !== $current['status']) {
            throw new RuntimeException('Concurrent result disagrees with persisted transition history');
        }
        if ($mode === 'retry' && $results !== ['OPEN','OPEN','OPEN']) throw new RuntimeException('Retry returned stale status');
        if ($mode === 'conflict' && (count(array_filter($results,fn($v)=>$v === 'CONFLICT')) !== 1 || !in_array($current['status'],$results,true))) throw new RuntimeException('Expected one winner and one conflict');
        echo "PASS: concurrent $mode writes one transition and returns current locked status despite older read snapshots.\n";
    }
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR,$e->getMessage()."\n"); exit(1);
}
