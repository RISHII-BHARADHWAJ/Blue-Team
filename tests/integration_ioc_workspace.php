<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db')exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
require_once __DIR__.'/../includes/soar/SiemSoarAlertPipeline.php';
require_once __DIR__.'/../includes/soar/IncidentIocWorkspace.php';
function iocCheck(bool $ok,string $message):void{if(!$ok)throw new RuntimeException('FAIL: '.$message);echo "PASS: $message\n";}
$pdo->beginTransaction();
try {
    $name='ioc-ci-'.bin2hex(random_bytes(6));
    $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name,'not-a-login-hash','analyst']);$uid=(int)$pdo->lastInsertId();
    $manager=new IncidentManager($pdo);$repo=new IncidentRepository($pdo);$service=new IncidentIocWorkspace($pdo);$iocRepo=new IocRepository($pdo);
    $case=$manager->createIncident(['title'=>$name,'severity'=>'HIGH']);$id=(int)$case['id'];
    $event=(new SiemSoarAlertPipeline($pdo))->ingest(['source'=>$name,'source_event_id'=>'ioc-context','source_ip'=>'9.9.9.9','destination_ip'=>'8.8.8.8','severity'=>'HIGH','category'=>'XSS','message'=>'Inspect 10.0.0.5 https://ioc-fixture.test/payload '.str_repeat('a',64),'metadata'=>['domain'=>'ioc-fixture.test','email'=>'analyst@ioc-fixture.test']],$name);
    $repo->attachAlert($id,(int)$event['log_id']);
    $beforeCase=$repo->find($id);
    $beforeEnrich=(int)$pdo->query('SELECT COUNT(*) FROM enrichment_results')->fetchColumn();
    iocCheck($service->read($id)['iocs']===[],'GET-style read creates no indicators');
    $result=$service->discover($id,$uid);
    iocCheck($result['new_links']===6 && $result['candidate_count']===6,'discovery includes canonical destination and metadata plus message URL/hash, excluding private IP');
    $byValue=[];foreach($service->read($id)['iocs'] as $row)$byValue[$row['ioc_value']]=$row;
    iocCheck($byValue['8.8.8.8']['role']==='TARGET' && $byValue['https://ioc-fixture.test/payload']['role']==='PAYLOAD_URL','candidate roles are inferred from stored telemetry');
    $iocId=(int)$byValue['ioc-fixture.test']['id'];
    $pdo->prepare('UPDATE iocs SET confidence_score=93,reputation_score=81 WHERE id=?')->execute([$iocId]);
    $pdo->prepare("UPDATE incident_iocs SET role='TARGET' WHERE incident_id=? AND ioc_id=?")->execute([$id,$iocId]);
    $beforeIoc=$iocRepo->find($iocId);$beforeTimeline=count((new IncidentTimeline($pdo))->getEvents($id));
    $again=$service->discover($id,$uid);
    iocCheck($again['new_links']===0 && $iocRepo->find($iocId)===$beforeIoc && count((new IncidentTimeline($pdo))->getEvents($id))===$beforeTimeline,'repeat discovery preserves registry metadata and emits no duplicate milestone');
    $selected=$service->read($id,1,$iocId)['selected'];
    iocCheck($selected['role']==='TARGET' && $selected['intelligence']['assessment']==='UNKNOWN','existing role preserved and registry reputation alone stays unknown');
    iocCheck($repo->find($id)===$beforeCase && (int)$pdo->query('SELECT COUNT(*) FROM enrichment_results')->fetchColumn()===$beforeEnrich,'discovery leaves risk, case fields and provider results unchanged');
    $stmt=$pdo->prepare("SELECT analyst FROM audit_log WHERE action='discover_incident_iocs' AND target=? ORDER BY id DESC LIMIT 1");$stmt->execute([$case['incident_number']]);
    iocCheck($stmt->fetchColumn()===$name,'discovery audit uses verified database analyst');
    $add=function(string $provider,int $rep,int $conf,string $status='SUCCESS',int $ttl=3600)use($iocRepo,$iocId):void{
        $iocRepo->saveEnrichmentResult($iocId,$provider,$status,['token'=>'RAW_SECRET'],['reputation'=>$rep,'confidence'=>$conf,'summary'=>['token'=>'SUMMARY_SECRET']],date('Y-m-d H:i:s',time()+$ttl));
    };
    $assessment=fn()=> $service->read($id,1,$iocId)['selected']['intelligence']['assessment'];
    $add('ci_provider',95,90);iocCheck($assessment()==='MALICIOUS','current saved malicious report contributes');
    $add('ci_provider',0,95);iocCheck($assessment()==='LOW_REPUTATION','newer result supersedes older malicious report including timestamp ties');
    $add('ci_provider',95,90,'FAILED');iocCheck($assessment()==='UNKNOWN','new failed lookup does not resurrect old success');
    $add('ci_provider',95,90,'SUCCESS',-1);iocCheck($assessment()==='UNKNOWN','expired result contributes no current evidence');
    $add('ci_provider',95,90);$add('ci_clean',0,95);iocCheck($assessment()==='CONFLICTING','conflicting current reports remain visible');
    $add('ci_clean',0,95,'RATE_LIMITED');iocCheck($assessment()==='MALICIOUS','rate-limited latest result is not a clean report');
    $iocRepo->saveEnrichmentResult($iocId,'ci_provider','SUCCESS',null,['reputation'=>'broken','confidence'=>90],date('Y-m-d H:i:s',time()+3600));
    iocCheck($assessment()==='UNKNOWN','malformed current scores remain unknown');
    $safe=json_encode($service->read($id,1,$iocId));
    iocCheck(!str_contains($safe,'RAW_SECRET')&&!str_contains($safe,'SUMMARY_SECRET')&&!str_contains($safe,'raw_response'),'workspace excludes raw payloads and arbitrary summary fields');
    $other=$manager->createIncident(['title'=>$name.' other']);$otherId=(int)$other['id'];
    $denied=false;try{$service->read($otherId,1,$iocId);}catch(OutOfBoundsException $e){$denied=true;}
    iocCheck($denied,'indicator detail is scoped to case');
    $repo->attachAlert($otherId,(int)$event['log_id']);
    $oldAgent=$_SERVER['HTTP_USER_AGENT']??null;$_SERVER['HTTP_USER_AGENT']="\xFF";$failed=false;
    try{$service->discover($otherId,$uid);}catch(PDOException $e){$failed=true;}
    if($oldAgent===null)unset($_SERVER['HTTP_USER_AGENT']);else $_SERVER['HTTP_USER_AGENT']=$oldAgent;
    iocCheck($failed && $pdo->inTransaction() && $service->read($otherId)['pagination']['total']===0,'failed audit rolls back new links and preserves caller transaction');
    $sim=$manager->createIncident(['title'=>$name.' sim','is_simulated'=>true]);$denied=false;
    try{$service->discover((int)$sim['id'],$uid);}catch(UnexpectedValueException $e){$denied=true;}
    iocCheck($denied,'simulated case cannot change global IOC inventory');
    $pdo->prepare('UPDATE users SET role=? WHERE id=?')->execute(['user',$uid]);$denied=false;
    try{$service->discover($id,$uid);}catch(DomainException $e){$denied=true;}
    iocCheck($denied,'revoked database role blocks discovery despite session tier');
    for($i=0;$i<26;$i++){$new=$iocRepo->upsertIoc(['ioc_type'=>'DOMAIN','ioc_value'=>"page-$i.$name.test"]);$iocRepo->attachToIncident($id,$new);$add('ci_provider',30,60);}
    $view=$service->read($id,1,$iocId);
    iocCheck(count($view['iocs'])===25 && count($view['history'])===25,'indicator list and lookup history are bounded');
    $last=$service->read($id,999999,$iocId,999999);
    iocCheck($last['pagination']['page']===$last['pagination']['pages'] && $last['historyPagination']['page']===$last['historyPagination']['pages'],'both pagers clamp to final page');
    $filtered=$service->read($id,1,null,1,'URL');
    iocCheck($filtered['pagination']['total']===1 && $filtered['iocs'][0]['ioc_type']==='URL','type filtering applies before pagination');
    $pdo->rollBack();echo "IOC workspace integration passed; fixtures rolled back.\n";
} catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
