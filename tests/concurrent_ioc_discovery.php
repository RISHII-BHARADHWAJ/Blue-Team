<?php
/** Concurrency fixture is confined to the disposable Compose database. */
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db')exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/IncidentIocWorkspace.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
require_once __DIR__.'/../includes/soar/SiemSoarAlertPipeline.php';
if(($argv[1]??'')==='worker'){
    try{$result=(new IncidentIocWorkspace($pdo))->discover((int)$argv[2],(int)$argv[3]);echo $result['new_links'];exit(0);}
    catch(Throwable $e){fwrite(STDERR,$e->getMessage());exit(1);}
}
try{
    $name='ioc_race_'.bin2hex(random_bytes(6));
    $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name,'not-a-login-hash','analyst']);$uid=(int)$pdo->lastInsertId();
    $case=(new IncidentManager($pdo))->createIncident(['title'=>$name]);$id=(int)$case['id'];
    $event=(new SiemSoarAlertPipeline($pdo))->ingest(['source'=>$name,'source_event_id'=>'race','source_ip'=>'10.0.0.12','severity'=>'HIGH','category'=>'XSS','message'=>'Hash '.hash('sha256',$name)],$name);
    (new IncidentRepository($pdo))->attachAlert($id,(int)$event['log_id']);
    $workers=[];$pdo->beginTransaction();(new IncidentRepository($pdo))->find($id,true);
    for($i=0;$i<3;$i++){
        $p=proc_open([PHP_BINARY,__FILE__,'worker',(string)$id,(string)$uid],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        if(!is_resource($p))throw new RuntimeException('Worker launch failed');fclose($pipes[0]);$workers[]=[$p,$pipes];
    }
    $pdo->commit();$created=0;
    foreach($workers as [$p,$pipes]){$out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0)throw new RuntimeException($err);$created+=(int)$out;}
    $stmt=$pdo->prepare('SELECT COUNT(*) FROM incident_iocs WHERE incident_id=?');$stmt->execute([$id]);
    if($created!==1||(int)$stmt->fetchColumn()!==1)throw new RuntimeException('Concurrent discovery duplicated or lost a link');
    $stmt=$pdo->prepare("SELECT COUNT(*) FROM incident_timeline WHERE incident_id=? AND JSON_UNQUOTE(JSON_EXTRACT(details,'$.event_subtype'))='IOCS_DISCOVERED'");$stmt->execute([$id]);
    if((int)$stmt->fetchColumn()!==1)throw new RuntimeException('Duplicate discovery milestones');
    echo "PASS: three simultaneous discoveries add one indicator link and one milestone.\n";
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
