<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db')exit(2);
require_once __DIR__.'/../includes/db.php';require_once __DIR__.'/../includes/soar/IncidentManager.php';
if(($argv[1]??'')==='worker'){
    try{
        $pdo->beginTransaction();$pdo->query('SELECT COUNT(*) FROM incidents')->fetchColumn();echo "READY\n";fflush(STDOUT);
        $row=(new IncidentManager($pdo))->assignIncident((int)$argv[2],(int)$argv[3],'concurrent-lead',null);
        $pdo->commit();echo (int)$row['assigned_to'];exit(0);
    }catch(IncidentAssignmentConflict $e){if($pdo->inTransaction())$pdo->rollBack();echo 'CONFLICT';exit(0);}
    catch(Throwable $e){fwrite(STDERR,$e->getMessage());exit(1);}
}
try{
    $name='assign-race-'.bin2hex(random_bytes(5));$users=[];
    foreach(['a','b'] as $suffix){$pdo->prepare("INSERT INTO users (username,password,role) VALUES (?,?,'analyst')")->execute([$name.$suffix,'not-a-login-hash']);$users[]=(int)$pdo->lastInsertId();}
    $manager=new IncidentManager($pdo);
    foreach(['retry','conflict'] as $mode){
        $case=$manager->createIncident(['title'=>$name.' '.$mode]);$id=(int)$case['id'];$pdo->beginTransaction();(new IncidentRepository($pdo))->find($id,true);
        $workers=[];$targets=$mode==='retry'?[$users[0],$users[0],$users[0]]:$users;
        foreach($targets as $target){$p=proc_open([PHP_BINARY,__FILE__,'worker',(string)$id,(string)$target],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($p))throw new RuntimeException('Could not start worker');fclose($pipes[0]);$workers[]=[$p,$pipes];}
        foreach($workers as [$p,$pipes])if(trim((string)fgets($pipes[1]))!=='READY')throw new RuntimeException('Worker did not establish snapshot');
        $pdo->commit();$results=[];
        foreach($workers as [$p,$pipes]){$out=trim(stream_get_contents($pipes[1]));$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0)throw new RuntimeException($err);$results[]=$out;}
        $stmt=$pdo->prepare('SELECT recipient_id FROM notifications WHERE incident_id=?');$stmt->execute([$id]);$notifications=$stmt->fetchAll(PDO::FETCH_COLUMN);
        $current=(new IncidentRepository($pdo))->find($id);
        if(count($notifications)!==1||(int)$notifications[0]!== (int)$current['assigned_to'])throw new RuntimeException('Concurrent handoff notification disagrees with owner');
        if($mode==='retry' && $results!==array_fill(0,3,(string)$users[0]))throw new RuntimeException('Same-target retry did not return current owner');
        if($mode==='conflict' && count(array_filter($results,fn($v)=>$v==='CONFLICT'))!==1)throw new RuntimeException('Competing stale assignment did not return one conflict');
        echo "PASS: concurrent $mode handoffs persist one owner and one notification with current results for older read snapshots.\n";
    }
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
