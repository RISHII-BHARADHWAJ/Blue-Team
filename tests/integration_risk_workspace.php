<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db'){fwrite(STDERR,"Disposable Compose CI only.\n");exit(2);}
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
require_once __DIR__.'/../includes/soar/SiemSoarAlertPipeline.php';
require_once __DIR__.'/../includes/soar/Risk/RiskScoringEngine.php';
function riskCheck(bool $ok,string $message):void{if(!$ok)throw new RuntimeException('FAIL: '.$message);echo "PASS: $message\n";}
function riskFactor(RiskAssessment $assessment,string $name):RiskFactor{foreach($assessment->factors as $f)if($f->name===$name)return $f;throw new RuntimeException('Missing factor');}
$pdo->beginTransaction();
try{
 $name='risk-ci-'.bin2hex(random_bytes(6));
 $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?, ?, ?)')->execute([$name,'not-a-login-hash','admin']);$uid=(int)$pdo->lastInsertId();
 $incident=(new IncidentManager($pdo))->createIncident(['title'=>$name,'severity'=>'HIGH']);$id=(int)$incident['id'];
 $engine=new RiskScoringEngine($pdo);$repo=new IncidentRepository($pdo);
 $firstView=$engine->workspace($id);
 riskCheck($firstView['latest']===null && $firstView['history']===[] && (int)$repo->find($id)['risk_score']===0,'reading unassessed case creates no assessment or score');
 $assessment=$engine->recalculateIncident($id,'spoofed actor',[],$uid);
 riskCheck($assessment->calculated_by===$name && $engine->getLatestAssessment($id)['calculated_by']===$name,'named actor reloaded from database and returned consistently');
 riskCheck($assessment->policy_version==='v1.1' && $repo->find($id)['priority']===$assessment->priority,'recalculation persists current policy and applies priority');
 $telemetry=(new SiemSoarAlertPipeline($pdo))->ingest(['source'=>$name,'source_event_id'=>'risk-context','source_ip'=>'9.9.9.9','destination_ip'=>'10.0.0.4','severity'=>'HIGH','category'=>'XSS','event_timestamp'=>'2001-01-01T00:00:00Z','message'=>'Disposable risk provenance fixture'], $name);
 $telemetryRisk=$engine->recalculateIncident((int)$telemetry['correlation']['incident_id'],$name,[],$uid);
 riskCheck(riskFactor($telemetryRisk,'network_context')->contribution===5 && riskFactor($telemetryRisk,'attack_recency')->contribution===0,'risk uses preserved destination and old source time from accepted telemetry');
 $old=$engine->getLatestAssessment($id);$oldId=(int)$old['id'];
 $pdo->prepare("UPDATE risk_assessments SET policy_version='v1.0' WHERE id=?")->execute([$oldId]);
 // Test only stored intelligence: no providers or network are invoked.
 $iocRepo=new IocRepository($pdo);$iocId=$iocRepo->upsertIoc(['ioc_type'=>'IPV4','ioc_value'=>'192.0.2.140','threat_type'=>'untrusted label','confidence_score'=>100]);
 $iocRepo->attachToIncident($id,$iocId,'ATTACKER');
 $unverified=$engine->recalculateIncident($id,$name,[],$uid);
 riskCheck(riskFactor($unverified,'ioc_reputation')->contribution===0,'IOC label without current provider evidence stays unknown');
 $add=function(string $provider,int $rep,int $confidence,string $status='SUCCESS',int $ttl=3600)use($pdo,$iocId):void{
  $pdo->prepare('INSERT INTO enrichment_results (ioc_id,provider,status,parsed_summary,cached_until,created_at) VALUES (?,?,?,?,?,?)')->execute([$iocId,$provider,$status,json_encode(['reputation'=>$rep,'confidence'=>$confidence]),gmdate('Y-m-d H:i:s',time()+$ttl),gmdate('Y-m-d H:i:s')]);
 };
 $add('ci_provider',95,90);
 $malicious=$engine->recalculateIncident($id,$name,[],$uid);
 riskCheck(riskFactor($malicious,'ioc_reputation')->contribution===15 && riskFactor($malicious,'ti_agreement')->contribution===2,'fresh successful provider evidence contributes with provenance');
 $add('ci_provider',0,95);
 $clean=$engine->recalculateIncident($id,$name,[],$uid);
 riskCheck(riskFactor($clean,'ioc_reputation')->contribution===0 && riskFactor($clean,'ti_agreement')->contribution===0,'newer clean result wins over old malicious result, including same-second ties');
 $add('ci_provider',95,95,'FAILED');
 riskCheck(riskFactor($engine->recalculateIncident($id,$name,[],$uid),'ioc_reputation')->value==='UNKNOWN','newest failed lookup cannot fall back to older success');
 $add('ci_provider',95,95,'SUCCESS',-1);
 riskCheck(riskFactor($engine->recalculateIncident($id,$name,[],$uid),'ioc_reputation')->contribution===0,'expired enrichment cannot contribute');
 $add('ci_provider',90,90);$add('ci_clean',0,95);
 riskCheck(riskFactor($engine->recalculateIncident($id,$name,[],$uid),'ioc_reputation')->value==='CONFLICTING','current contradictory providers remain conflicting');
 $historical=$engine->workspace($id,1,$oldId)['selected'];
 riskCheck($historical['policy_version']==='v1.0' && $historical['factor_breakdown']===$old['factor_breakdown'],'earlier policy and stored factor breakdown preserved');
 $another=(new IncidentManager($pdo))->createIncident(['title'=>$name.'-other']);$otherId=(int)$another['id'];
 $wrong=false;try{$engine->workspace($otherId,1,$oldId);}catch(InvalidArgumentException $e){$wrong=true;}
 riskCheck($wrong,'historical assessment lookup is scoped to its incident');
 // Force a failure AFTER score/history/priority writes, at audit insertion.
 $before=$repo->find($id);$countBefore=$engine->workspace($id)['pagination']['total'];
 $oldAgent=$_SERVER['HTTP_USER_AGENT']??null;$_SERVER['HTTP_USER_AGENT']="\xFF";$failed=false;
 try{$engine->recalculateIncident($id,$name,[],$uid);}catch(PDOException $e){$failed=true;}
 if($oldAgent===null)unset($_SERVER['HTTP_USER_AGENT']);else $_SERVER['HTTP_USER_AGENT']=$oldAgent;
 riskCheck($failed && $pdo->inTransaction() && $engine->workspace($id)['pagination']['total']===$countBefore && $repo->find($id)===$before,'failed audit rolls back assessment and priority while preserving caller transaction');
 // Bounded history and same-second ordering using already valid stored factors.
 $stmt=$pdo->prepare('INSERT INTO risk_assessments (incident_id,score,priority,confidence,factor_breakdown,policy_version,calculated_at,calculated_by) VALUES (?,?,?,?,?,?,?,?)');
 for($i=0;$i<26;$i++)$stmt->execute([$id,22,'P4','LOW',json_encode($old['factor_breakdown']),'v1.1','2090-01-01 00:00:00',$name]);
 $lastId=(int)$pdo->lastInsertId();$view=$engine->workspace($id);
 riskCheck(count($view['history'])===25 && (int)$view['latest']['id']===$lastId,'history is bounded and newest ID resolves timestamp ties');
 $page=$engine->workspace($id,999999);riskCheck($page['pagination']['page']===$page['pagination']['pages'] && count($page['history'])>0,'history pagination clamps to final page');
 $pdo->prepare('UPDATE users SET role=? WHERE id=?')->execute(['user',$uid]);$denied=false;
 try{$engine->recalculateIncident($id,$name,[],$uid);}catch(DomainException $e){$denied=true;}
 riskCheck($denied && $pdo->inTransaction(),'revoked database role blocks recalculation inside caller transaction');
 $pdo->rollBack();echo "Risk workspace integration passed; fixtures rolled back.\n";
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
