<?php
/** Retry race test; fixture remains only in the disposable Compose database. */
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db')exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/playbooks/PlaybookWorkspace.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
if(($argv[1]??'')==='worker'){
 try{$run=(new PlaybookWorkspace($pdo))->preview((int)$argv[2],(int)$argv[3],1,(int)$argv[4],$argv[5]);echo $run['id'];exit(0);}
 catch(Throwable $e){fwrite(STDERR,$e->getMessage());exit(1);}
}
try{
 $name='preview_race_'.bin2hex(random_bytes(6));
 $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name,'not-a-login-hash','user']);$uid=(int)$pdo->lastInsertId();
 $case=(new IncidentManager($pdo))->createIncident(['title'=>$name,'is_simulated'=>true]);$id=(int)$case['id'];
 $pb=(int)$pdo->query("SELECT id FROM playbooks WHERE playbook_name='simulated_investigation_v1'")->fetchColumn();
 $key=bin2hex(random_bytes(16));$workers=[];$pdo->beginTransaction();(new IncidentRepository($pdo))->find($id,true);
 for($i=0;$i<3;$i++){
  $p=proc_open([PHP_BINARY,__FILE__,'worker',(string)$id,(string)$pb,(string)$uid,$key],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
  if(!is_resource($p))throw new RuntimeException('Could not launch worker');fclose($pipes[0]);$workers[]=[$p,$pipes];
 }
 $pdo->commit();$ids=[];
 foreach($workers as [$p,$pipes]){$out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);if(proc_close($p)!==0)throw new RuntimeException($err);$ids[]=(int)$out;}
 $stmt=$pdo->prepare('SELECT COUNT(*) FROM playbook_runs WHERE incident_id=?');$stmt->execute([$id]);
 if(count(array_unique($ids))!==1||$ids[0]<1||(int)$stmt->fetchColumn()!==1)throw new RuntimeException('Concurrent retry created duplicate runs');
 $stmt=$pdo->prepare('SELECT COUNT(*) FROM playbook_step_results WHERE playbook_run_id=?');$stmt->execute([$ids[0]]);
 if((int)$stmt->fetchColumn()!==3)throw new RuntimeException('Concurrent retry duplicated or lost step results');
 echo "PASS: three simultaneous preview submissions return one run and one set of step results.\n";
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
