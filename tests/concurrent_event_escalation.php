<?php
declare(strict_types=1);
require_once __DIR__.'/event_escalation_fixtures.php';
if (($argv[1]??'')==='worker') {
    try {
        $auth=['auth_method'=>'session','user_id'=>(int)$argv[3]];
        // Establish a stale snapshot before waiting on the parent's evidence lock.
        $pdo->beginTransaction();$pdo->query('SELECT COUNT(*) FROM incidents')->fetchColumn();
        echo "READY\n";fflush(STDOUT);
        $result=(new EventEscalationService($pdo))->escalate((int)$argv[2],$auth,'Concurrent event investigation','Concurrent rationale');
        $pdo->commit();echo $result['incident_id'];exit(0);
    } catch(Throwable $e) { fwrite(STDERR,$e->getMessage());exit(1); }
}
try {
    $name='escalate-race-'.bin2hex(random_bytes(5));$uid=escalationUser($pdo,$name);$id=escalationFixture($pdo,$name);
    $pdo->beginTransaction();$stmt=$pdo->prepare('SELECT id FROM event_evidence WHERE log_id=? FOR UPDATE');$stmt->execute([$id]);
    $workers=[];
    for($i=0;$i<3;$i++) {
        $p=proc_open([PHP_BINARY,__FILE__,'worker',(string)$id,(string)$uid],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        if(!is_resource($p))throw new RuntimeException('Could not launch worker');fclose($pipes[0]);$workers[]=[$p,$pipes];
    }
    foreach($workers as [$p,$pipes]) {
        if(trim((string)fgets($pipes[1]))!=='READY')throw new RuntimeException('Worker did not establish its initial snapshot');
    }
    $pdo->commit();$ids=[];
    foreach($workers as [$p,$pipes]) {
        $out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
        if(proc_close($p)!==0)throw new RuntimeException($err);$ids[]=(int)$out;
    }
    $stmt=$pdo->prepare('SELECT COUNT(*) FROM incident_alerts WHERE log_id=?');$stmt->execute([$id]);
    if(count(array_unique($ids))!==1 || $ids[0]<1 || (int)$stmt->fetchColumn()!==1)throw new RuntimeException('Concurrent submissions duplicated cases');
    $stmt=$pdo->prepare('SELECT COUNT(*) FROM case_notes WHERE incident_id=?');$stmt->execute([$ids[0]]);
    if((int)$stmt->fetchColumn()!==1)throw new RuntimeException('Concurrent submissions duplicated rationale');
    echo "PASS: simultaneous event escalations return one case and one rationale, including callers with existing transactions.\n";
} catch(Throwable $e) { if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1); }
