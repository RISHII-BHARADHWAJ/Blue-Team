<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') {
    fwrite(STDERR, "Refusing to run outside disposable Compose CI.\n"); exit(2);
}
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/soar/DemoService.php';
require_once __DIR__ . '/../includes/soar/IncidentIocService.php';
require_once __DIR__ . '/../includes/soar/CaseNoteService.php';
function demoCheck(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: ' . $message);
    echo "PASS: $message\n";
}
function demoDenied(callable $call): bool {
    try { $call(); return false; } catch (DomainException|InvalidArgumentException $e) { return true; }
}
SoarAuth::getContext($pdo);
$pdo->beginTransaction();
try {
    $name='demo-ci-'.bin2hex(random_bytes(6));
    $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?, ?, ?)')->execute([$name,'not-a-login-hash','admin']);
    $uid=(int)$pdo->lastInsertId();
    $_SESSION=['user_id'=>$uid,'analyst'=>$name,'role'=>'admin'];
    $pdo->exec("UPDATE detection_rules SET enabled=1, threshold_count=3, window_seconds=300, severity='MEDIUM' WHERE rule_key='auth_failures'");
    $ruleBefore=$pdo->query("SELECT * FROM detection_rules WHERE rule_key='auth_failures'")->fetch(PDO::FETCH_ASSOC);
    $repo=new IncidentRepository($pdo); $service=new DemoService($pdo); $key=bin2hex(random_bytes(16));
    $realBefore=$repo->countIncidents();
    $session=$service->create($uid,$key); $id=(int)$session['incident_id'];
    $incident=(new IncidentManager($pdo))->getIncident($id);
    demoCheck((int)$incident['is_simulated']===1 && $incident['severity']==='MEDIUM' && count($incident['alerts'])===3, 'demo uses configured threshold and severity');
    demoCheck($ruleBefore===$pdo->query("SELECT * FROM detection_rules WHERE rule_key='auth_failures'")->fetch(PDO::FETCH_ASSOC), 'demo leaves rule configuration unchanged');
    demoCheck((int)$service->create($uid,$key)['id']===(int)$session['id'], 'repeated submission returns the same demo');
    demoCheck($repo->countIncidents()===$realBefore && $repo->countIncidents(['kind'=>'simulated'])>=1, 'default count excludes simulated cases');
    demoCheck(!in_array($id,array_column($repo->listIncidents(),'id')), 'default case list excludes simulated cases');
    demoCheck(!in_array($id,array_column($repo->findActiveIncidentsForCorrelation('2000-01-01','192.0.2.55'),'id')), 'real correlation excludes simulated case');
    $stmt=$pdo->prepare('SELECT incident_id, is_simulated FROM detection_findings WHERE id=?');$stmt->execute([$session['finding_id']]);$f=$stmt->fetch();
    demoCheck((int)$f['incident_id']===$id && (int)$f['is_simulated']===1, 'simulated finding links to simulated case');
    demoCheck(demoDenied(fn()=>$repo->update($id,['is_simulated'=>0])), 'simulation classification cannot be changed');
    $pipeline=new SiemSoarAlertPipeline($pdo);
    $ordinary=$pipeline->ingest(['source'=>$name,'source_event_id'=>'generic','source_ip'=>'192.0.2.55','severity'=>'HIGH','message'=>'Training','is_simulated'=>true],$name);
    demoCheck($ordinary['correlation']['incident_id']===null, 'generic simulated ingestion still creates no case');
    $real=$pipeline->ingest(['source'=>$name,'source_event_id'=>'real','source_ip'=>'192.0.2.55','severity'=>'HIGH','message'=>'Real test fixture','is_simulated'=>false],$name);
    $realId=(int)$real['correlation']['incident_id'];
    demoCheck($realId>0 && $realId!==$id && !(bool)$repo->find($realId)['is_simulated'], 'real event at the same IP creates a separate real case');
    demoCheck(demoDenied(fn()=>$repo->attachAlert($realId,(int)$incident['alerts'][0]['log_id'])), 'simulated evidence rejected by real case');
    demoCheck(demoDenied(fn()=>$repo->attachAlert($id,(int)$real['log_id'])), 'real evidence rejected by simulated case');
    demoCheck(demoDenied(fn()=>(new IncidentManager($pdo))->escalateAlertToIncident((int)$ordinary['log_id'],$name)), 'manual escalation of generic simulated evidence remains blocked');
    demoCheck(demoDenied(fn()=>(new IncidentIocService($pdo))->processIncidentIocs($id)), 'live enrichment blocked before IOC writes or provider calls');
    $manager=new IncidentManager($pdo);
    $manager->changeStatus($id,'OPEN',$name,'Practice triage');
    $manager->changeStatus($id,'INVESTIGATING',$name,'Review supporting evidence');
    (new CaseNoteService($pdo))->add($id,$uid,'Simulated investigation note');
    $manager->changeStatus($id,'RESOLVED',$name,'Training completed');
    demoCheck($repo->find($id)['status']==='RESOLVED', 'training case supports normal triage and notes');

    // Exercise all current allowlisted action types on the simulated incident.
    $pb=new PlaybookRepository($pdo);
    $pbid=(int)$pdo->query("SELECT id FROM playbooks WHERE playbook_name='simulated_investigation_v1'")->fetchColumn();
    foreach ([['ENRICH_IOCS',[]],['ADD_INCIDENT_NOTE',['note'=>'Must remain preview']],['CREATE_EVIDENCE_RECORD',['title'=>'Must remain preview']]] as $i=>$item) {
        $pb->createStep($pbid,['step_order'=>$i+4,'step_name'=>$item[0],'action_type'=>$item[0],'action_parameters'=>$item[1]]);
    }
    $before=[];
    foreach (['approval_requests','notifications','evidence','case_notes','incident_iocs','response_actions'] as $table) $before[$table]=(int)$pdo->query("SELECT COUNT(*) FROM $table")->fetchColumn();
    $preview=$service->preview((int)$session['id'],$uid);
    $run=$pb->findRun((int)$preview['playbook_run_id']);
    demoCheck($run['status']==='COMPLETED' && $run['execution_context']['mode']==='DRY_RUN', 'preview completes and persists dry-run mode');
    demoCheck((int)$service->preview((int)$session['id'],$uid)['playbook_run_id']===(int)$run['id'], 'preview retry returns same run');
    $steps=$pb->getStepResults((int)$run['id']);
    demoCheck(count($steps)===6, 'all six allowlisted actions previewed');
    foreach ($steps as $step) demoCheck((int)$step['is_dry_run']===1 && $step['status']==='SUCCESS', $step['action_type'].' recorded as successful preview');
    foreach (['MANUAL','AUTOMATIC'] as $mode) {
        $forced=(new PlaybookEngine($pdo))->startRun($pbid,$id,$mode,['id'=>$uid,'username'=>$name,'tier'=>'ADMIN']);
        demoCheck($forced['execution_context']['mode']==='DRY_RUN', "$mode request forced to dry-run by authoritative incident state");
    }
    foreach ($before as $table=>$count) demoCheck((int)$pdo->query("SELECT COUNT(*) FROM $table")->fetchColumn()===$count, "preview produces no $table side effects");
    $sessionsBefore=(int)$pdo->query('SELECT COUNT(*) FROM demo_sessions')->fetchColumn();
    $pdo->exec("UPDATE detection_rules SET enabled=0 WHERE rule_key='auth_failures'");
    $disabled=false;try{$service->create($uid,bin2hex(random_bytes(16)));}catch(UnexpectedValueException $e){$disabled=true;}
    demoCheck($disabled && (int)$pdo->query('SELECT COUNT(*) FROM demo_sessions')->fetchColumn()===$sessionsBefore && $pdo->inTransaction(), 'disabled rule rejects and rolls back only failed demo');
    $pdo->prepare('UPDATE users SET role=? WHERE id=?')->execute(['user',$uid]);
    demoCheck(demoDenied(fn()=>$service->create($uid,bin2hex(random_bytes(16)))), 'revoked role rechecked from database');
    demoCheck(demoDenied(fn()=>$service->preview((int)$session['id'],$uid)), 'revoked role cannot start or replay preview');
    $pdo->rollBack(); echo "Demo integration passed; fixtures rolled back.\n";
} catch (Throwable $e) { if($pdo->inTransaction())$pdo->rollBack(); fwrite(STDERR,$e->getMessage()."\n");exit(1); }
