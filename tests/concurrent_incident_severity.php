<?php
declare(strict_types=1);
require_once __DIR__.'/audit_history_fixtures.php';
require_once __DIR__.'/../includes/soar/IncidentSeverityService.php';
if (($argv[1] ?? '') === 'worker') {
    try {
        $pdo->beginTransaction();$pdo->query('SELECT COUNT(*) FROM incidents')->fetchColumn();echo "READY\n";fflush(STDOUT);
        $result=(new IncidentSeverityService($pdo))->change(['auth_method'=>'session','user_id'=>(int)$argv[3]],(int)$argv[2],$argv[4],'MEDIUM','P3','Concurrent assessment');
        $pdo->commit();echo $result['incident']['severity'];exit(0);
    } catch (IncidentSeverityConflict $e) {if($pdo->inTransaction())$pdo->rollBack();echo 'CONFLICT';exit(0);}
    catch(Throwable $e){fwrite(STDERR,$e->getMessage());exit(1);}
}
try {
    $name='severity-race-'.bin2hex(random_bytes(5));$uid=auditUser($pdo,$name,'lead');$manager=new IncidentManager($pdo);
    foreach (['retry','conflict'] as $mode) {
        $case=$manager->createIncident(['title'=>$name.'-'.$mode]);$id=(int)$case['id'];
        $pdo->beginTransaction();$pdo->query('SELECT id FROM incidents WHERE id='.$id.' FOR UPDATE')->fetchColumn();
        $workers=[];
        foreach ($mode==='retry'?['HIGH','HIGH','HIGH']:['HIGH','LOW'] as $target) {
            $process=proc_open([PHP_BINARY,__FILE__,'worker',(string)$id,(string)$uid,$target],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
            if(!is_resource($process))throw new RuntimeException('Could not start worker');fclose($pipes[0]);$workers[]=[$process,$pipes];
        }
        foreach($workers as [$process,$pipes])if(trim((string)fgets($pipes[1]))!=='READY')throw new RuntimeException('Worker failed to establish snapshot');
        $pdo->commit();$results=[];
        foreach($workers as [$process,$pipes]){$out=trim(stream_get_contents($pipes[1]));$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($process)!==0)throw new RuntimeException($err);$results[]=$out;}
        $current=$pdo->query('SELECT severity,priority FROM incidents WHERE id='.$id)->fetch(PDO::FETCH_ASSOC);
        foreach(['case_notes','incident_timeline'] as $table){$suffix=$table==='incident_timeline'?" AND event_type='SEVERITY_CHANGE'":'';if((int)$pdo->query("SELECT COUNT(*) FROM $table WHERE incident_id=$id".$suffix)->fetchColumn()!==1)throw new RuntimeException('Duplicate or missing '.$table);}
        $stmt=$pdo->prepare("SELECT details FROM audit_log WHERE target=? AND action='change_incident_severity'");$stmt->execute(['incident:'.$id]);$audits=$stmt->fetchAll(PDO::FETCH_COLUMN);
        if(count($audits)!==1 || json_decode($audits[0],true)['new_severity']!==$current['severity'] || json_decode($audits[0],true)['new_priority']!==$current['priority'])throw new RuntimeException('Audit disagrees with winning assessment');
        if($mode==='retry' && $results!==['HIGH','HIGH','HIGH'])throw new RuntimeException('Retry returned stale severity');
        if($mode==='conflict' && (count(array_filter($results,fn($r)=>$r==='CONFLICT'))!==1 || !in_array($current['severity'],$results,true)))throw new RuntimeException('Expected one conflict and one winner');
        echo "PASS: concurrent severity $mode writes one assessment and returns current values despite older snapshots.\n";
    }
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
