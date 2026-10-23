<?php
declare(strict_types=1);
require_once __DIR__.'/event_escalation_fixtures.php';require_once __DIR__.'/../includes/soar/IncidentEvidenceWorkspace.php';
if(($argv[1]??'')==='worker'){
    try{
        $pdo->beginTransaction();$pdo->query('SELECT COUNT(*) FROM incident_alerts')->fetchColumn();echo "READY\n";fflush(STDOUT);
        $r=(new IncidentEvidenceWorkspace($pdo))->attach((int)$argv[2],(int)$argv[3],['auth_method'=>'session','user_id'=>(int)$argv[4]],'Concurrent rationale');
        $pdo->commit();echo $r['added']?'ADDED':'EXISTING';exit(0);
    }catch(Throwable $e){fwrite(STDERR,$e->getMessage());exit(1);}
}
try{
    $name='evidence-race-'.bin2hex(random_bytes(5));$uid=escalationUser($pdo,$name);$logId=escalationFixture($pdo,$name);
    $case=(new IncidentManager($pdo))->createIncident(['title'=>$name]);$id=(int)$case['id'];
    $pdo->beginTransaction();$stmt=$pdo->prepare('SELECT id FROM event_evidence WHERE log_id=? FOR UPDATE');$stmt->execute([$logId]);
    $workers=[];
    for($i=0;$i<3;$i++){$p=proc_open([PHP_BINARY,__FILE__,'worker',(string)$id,(string)$logId,(string)$uid],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p))throw new RuntimeException('Could not launch worker');fclose($pipes[0]);$workers[]=[$p,$pipes];}
    foreach($workers as [$p,$pipes])if(trim((string)fgets($pipes[1]))!=='READY')throw new RuntimeException('Worker did not establish snapshot');
    $pdo->commit();$results=[];
    foreach($workers as [$p,$pipes]){$out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0)throw new RuntimeException($err);$results[]=$out;}
    sort($results);if($results!==['ADDED','EXISTING','EXISTING'])throw new RuntimeException('Concurrent attachments did not resolve to one addition');
    foreach(['incident_alerts','case_notes'] as $table){$stmt=$pdo->prepare("SELECT COUNT(*) FROM $table WHERE incident_id=?");$stmt->execute([$id]);if((int)$stmt->fetchColumn()!==1)throw new RuntimeException('Duplicate '.$table.' rows');}
    echo "PASS: simultaneous evidence attachments with prior snapshots save one link and one rationale.\n";
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
