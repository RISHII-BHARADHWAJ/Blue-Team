<?php
declare(strict_types=1);
require_once __DIR__.'/audit_history_fixtures.php';
require_once __DIR__.'/../includes/soar/ManualCaseService.php';
if(($argv[1]??'')==='worker'){
    try{
        $pdo->beginTransaction();$pdo->query('SELECT COUNT(*) FROM manual_case_requests')->fetchColumn();echo "READY\n";fflush(STDOUT);
        $result=(new ManualCaseService($pdo))->create(['auth_method'=>'session','user_id'=>(int)$argv[2]],$argv[3],$argv[4],'HIGH','Concurrent report');
        $pdo->commit();echo json_encode($result);exit(0);
    }catch(ManualCaseConflict $e){if($pdo->inTransaction())$pdo->rollBack();echo 'CONFLICT';exit(0);}
    catch(Throwable $e){fwrite(STDERR,$e->getMessage());exit(1);}
}
try{
    $name='intake-race-'.bin2hex(random_bytes(5));$uid=auditUser($pdo,$name,'analyst');
    foreach(['retry','conflict'] as $mode){
        $key=bin2hex(random_bytes(16));
        // Hold the user row until all workers establish older read snapshots.
        $pdo->beginTransaction();$pdo->query('SELECT id FROM users WHERE id='.$uid.' FOR UPDATE')->fetchColumn();$workers=[];
        foreach($mode==='retry'?[$name,$name,$name]:[$name,$name.' changed'] as $title){
            $process=proc_open([PHP_BINARY,__FILE__,'worker',(string)$uid,$key,$title],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
            if(!is_resource($process))throw new RuntimeException('Could not start worker');fclose($pipes[0]);$workers[]=[$process,$pipes];
        }
        foreach($workers as [$process,$pipes])if(trim((string)fgets($pipes[1]))!=='READY')throw new RuntimeException('Worker failed to establish snapshot');
        $pdo->commit();$results=[];
        foreach($workers as [$process,$pipes]){$out=trim(stream_get_contents($pipes[1]));$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($process)!==0)throw new RuntimeException($err);$results[]=$out;}
        $stmt=$pdo->prepare('SELECT incident_id FROM manual_case_requests WHERE user_id=? AND request_key=?');$stmt->execute([$uid,$key]);$id=(int)$stmt->fetchColumn();
        $success=array_map(fn($r)=>json_decode($r,true),array_values(array_filter($results,fn($r)=>$r!=='CONFLICT')));
        if(count(array_filter($success,fn($r)=>$r['created']))!==1 || count(array_filter($success,fn($r)=>$r['incident_id']!==$id))!==0)throw new RuntimeException('Request identity did not converge on one case');
        if(($mode==='retry' && count($success)!==3)||($mode==='conflict' && count($success)!==1))throw new RuntimeException('Unexpected retry/conflict result');
        if((int)$pdo->query('SELECT COUNT(*) FROM case_notes WHERE incident_id='.$id)->fetchColumn()!==1)throw new RuntimeException('Duplicate initial reports');
        $stmt=$pdo->prepare("SELECT COUNT(*) FROM audit_log WHERE action='create_manual_case' AND target=?");$stmt->execute(['incident:'.$id]);if((int)$stmt->fetchColumn()!==1)throw new RuntimeException('Duplicate creation audits');
        echo "PASS: concurrent manual intake $mode creates one case and preserves request identity across older snapshots.\n";
    }
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
