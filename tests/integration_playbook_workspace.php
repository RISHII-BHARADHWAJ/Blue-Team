<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db')exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/playbooks/PlaybookWorkspace.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
function previewCheck(bool $ok,string $msg):void{if(!$ok)throw new RuntimeException('FAIL: '.$msg);echo "PASS: $msg\n";}
$pdo->beginTransaction();
try{
 $name='preview_ci_'.bin2hex(random_bytes(6));
 $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name,'not-a-login-hash','user']);$uid=(int)$pdo->lastInsertId();
 $manager=new IncidentManager($pdo);$incident=$manager->createIncident(['title'=>$name,'severity'=>'HIGH']);$id=(int)$incident['id'];
 $other=$manager->createIncident(['title'=>$name.'-other']);$otherId=(int)$other['id'];
 $repo=new PlaybookRepository($pdo);$service=new PlaybookWorkspace($pdo);
 $pb=$repo->createPlaybook(['playbook_name'=>$name,'display_name'=>'CI preview','category'=>'INVESTIGATION','requires_approval'=>0],$uid);
 foreach([['COLLECT_INCIDENT_CONTEXT',[]],['REQUEST_APPROVAL',[]],['NOTIFY_ANALYST',['title'=>'Preview notification']],['ADD_INCIDENT_NOTE',['note'=>'Preview note']],['ENRICH_IOCS',[]],['CREATE_EVIDENCE_RECORD',['title'=>'Preview evidence']]] as $i=>$step){
  $repo->createStep($pb,['step_order'=>$i+1,'step_name'=>'Step '.($i+1),'action_type'=>$step[0],'action_parameters'=>$step[1]]);
 }
 $view=$service->read($id,1,null,$pb);
 previewCheck($view['runs']===[] && count($view['steps'])===6,'read-only workspace shows definition and empty history');
 $before=[];foreach(['approval_requests','notifications','case_notes','evidence','incident_iocs','response_actions'] as $t)$before[$t]=(int)$pdo->query("SELECT COUNT(*) FROM $t")->fetchColumn();
 $key=bin2hex(random_bytes(16));$run=$service->preview($id,$pb,1,$uid,$key);$runId=(int)$run['id'];
 previewCheck($run['status']==='COMPLETED' && $run['execution_context']['mode']==='DRY_RUN','named Tier 1 user completes forced dry-run for a real case');
 previewCheck((int)$run['analyst_id']===$uid && count($run['execution_context']['definition_snapshot']['steps'])===6,'verified analyst and full definition snapshot persisted');
 foreach($repo->getStepResults($runId) as $step)previewCheck($step['status']==='SUCCESS' && (int)$step['is_dry_run']===1,$step['action_type'].' is preview-only');
 foreach($before as $t=>$count)previewCheck((int)$pdo->query("SELECT COUNT(*) FROM $t")->fetchColumn()===$count,"no $t side effects");
 previewCheck((int)$service->preview($id,$pb,1,$uid,$key)['id']===$runId,'identical submission returns same run');
 $conflict=false;try{$service->preview($otherId,$pb,1,$uid,$key);}catch(UnexpectedValueException $e){$conflict=true;}
 previewCheck($conflict,'same key cannot silently refer to another case');
 $cross=false;try{$service->read($otherId,1,$runId);}catch(OutOfBoundsException $e){$cross=true;}
 previewCheck($cross,'run detail is scoped to the case');
 $pdo->prepare('UPDATE playbooks SET version=2, display_name=? WHERE id=?')->execute(['Changed name',$pb]);
 $stale=false;try{$service->preview($id,$pb,1,$uid,bin2hex(random_bytes(16)));}catch(UnexpectedValueException $e){$stale=true;}
 previewCheck($stale,'stale definition version rejected');
 previewCheck($service->read($id,1,$runId)['run']['execution_context']['definition_snapshot']['playbook']['display_name']==='CI preview','saved definition remains unchanged after catalog edit');
 previewCheck((int)$service->preview($id,$pb,1,$uid,$key)['id']===$runId,'replay of completed intent survives later catalog edits');
 $pdo->prepare('UPDATE playbooks SET is_active=0 WHERE id=?')->execute([$pb]);$disabled=false;
 try{$service->preview($id,$pb,2,$uid,bin2hex(random_bytes(16)));}catch(UnexpectedValueException $e){$disabled=true;}
 previewCheck($disabled,'disabled playbook cannot start a new preview');
 $pdo->prepare('UPDATE playbooks SET is_active=1 WHERE id=?')->execute([$pb]);
 // Handler validation failure is a saved FAILED result, not a fabricated completion.
 $failedPb=$repo->createPlaybook(['playbook_name'=>$name.'_failed','display_name'=>'Missing note','category'=>'INVESTIGATION'],$uid);
 $repo->createStep($failedPb,['step_order'=>1,'step_name'=>'Empty note','action_type'=>'ADD_INCIDENT_NOTE','action_parameters'=>[]]);
 $failedKey=bin2hex(random_bytes(16));$failed=$service->preview($id,$failedPb,1,$uid,$failedKey);
 previewCheck($failed['status']==='FAILED' && (int)$service->preview($id,$failedPb,1,$uid,$failedKey)['id']===(int)$failed['id'],'failed preview remains inspectable and retry does not run again');
 $empty=$repo->createPlaybook(['playbook_name'=>$name.'_empty','display_name'=>'Empty','category'=>'INVESTIGATION'],$uid);
 $beforeRequests=(int)$pdo->query('SELECT COUNT(*) FROM playbook_preview_requests')->fetchColumn();$invalid=false;
 try{$service->preview($id,$empty,1,$uid,bin2hex(random_bytes(16)));}catch(UnexpectedValueException $e){$invalid=true;}
 previewCheck($invalid && $pdo->inTransaction() && (int)$pdo->query('SELECT COUNT(*) FROM playbook_preview_requests')->fetchColumn()===$beforeRequests,'invalid definition rolls back request and preserves caller transaction');
 $deleted=false;try{$service->preview($id,$pb,2,2147483647,bin2hex(random_bytes(16)));}catch(DomainException $e){$deleted=true;}
 previewCheck($deleted,'missing database user cannot impersonate analyst');
 // Existing live approval behavior stays gated (no approval decision is made).
 $live=$repo->createPlaybook(['playbook_name'=>$name.'_approval','display_name'=>'Approval gate','category'=>'INVESTIGATION'],$uid);
 $repo->createStep($live,['step_order'=>1,'step_name'=>'Approval','action_type'=>'REQUEST_APPROVAL','action_parameters'=>[]]);
 $liveRun=(new PlaybookEngine($pdo))->startRun($live,$id,'MANUAL',['id'=>$uid,'username'=>$name,'tier'=>'ADMIN']);
 previewCheck($liveRun['status']==='WAITING_APPROVAL' && $repo->findPendingApproval((int)$liveRun['id'])!==null,'live runs still require real approval');
 $sim=$manager->createIncident(['title'=>$name.'-simulated','is_simulated'=>true]);
 $simRun=$service->preview((int)$sim['id'],$pb,2,$uid,bin2hex(random_bytes(16)));
 previewCheck($simRun['execution_context']['mode']==='DRY_RUN' && $simRun['status']==='COMPLETED','simulation isolation retained');
 // Pagination is bounded, and latest IDs determine order even at equal timestamps.
 for($i=0;$i<26;$i++)$repo->createRun($pb,$id,'ANALYST',$uid,bin2hex(random_bytes(16)),['mode'=>'DRY_RUN'],2);
 $history=$service->read($id);previewCheck(count($history['runs'])===25,'run history bounded to 25 entries');
 $last=$service->read($id,99999);previewCheck($last['pagination']['page']===$last['pagination']['pages'] && count($last['runs'])>0,'history pagination clamps to last page');
 $pdo->rollBack();echo "Playbook workspace integration passed; fixtures rolled back.\n";
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
