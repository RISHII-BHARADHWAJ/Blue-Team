<?php
declare(strict_types=1);
require_once __DIR__.'/audit_history_fixtures.php';
require_once __DIR__.'/../includes/soar/IncidentSeverityService.php';
function severityCheck(bool $ok,string $message): void { if (!$ok) throw new RuntimeException('FAIL: '.$message);echo "PASS: $message\n"; }
function severityState(PDO $pdo,int $id): array {
    $stmt=$pdo->prepare('SELECT severity,priority,risk_score,status,updated_at FROM incidents WHERE id=?');$stmt->execute([$id]);$case=$stmt->fetch(PDO::FETCH_ASSOC);
    foreach (['case_notes','incident_timeline'] as $table) {$stmt=$pdo->prepare("SELECT COUNT(*) FROM $table WHERE incident_id=?");$stmt->execute([$id]);$case[$table]=(int)$stmt->fetchColumn();}
    $stmt=$pdo->prepare("SELECT COUNT(*) FROM audit_log WHERE target=? AND action='change_incident_severity'");$stmt->execute(['incident:'.$id]);$case['audits']=(int)$stmt->fetchColumn();return $case;
}
$service=new IncidentSeverityService($pdo);$pdo->beginTransaction();
try {
    $name='severity-ci-'.bin2hex(random_bytes(5));$admin=auditUser($pdo,$name.'-admin','admin');$lead=auditUser($pdo,$name.'-lead','lead');$analyst=auditUser($pdo,$name.'-analyst','analyst');$reader=auditUser($pdo,$name.'-reader','user');
    $auth=['auth_method'=>'session','user_id'=>$admin,'tier'=>'TIER1','actor'=>'spoofed'];
    $manager=new IncidentManager($pdo);$case=$manager->createIncident(['title'=>$name]);$id=(int)$case['id'];
    $pdo->prepare("UPDATE incidents SET risk_score=73,updated_at='2020-01-01 00:00:00' WHERE id=?")->execute([$id]);
    $reason=str_repeat('Evidence assessed. ',90).'Unicode: 日本語 <script>reasonProbe()</script>';
    $first=$service->change($auth,$id,'HIGH','MEDIUM','P3',$reason);$state=severityState($pdo,$id);
    severityCheck($first['changed'] && $state['severity']==='HIGH' && $state['priority']==='P2' && (int)$state['risk_score']===73 && $state['status']==='NEW','current database admin changes severity and mapped priority without changing risk or lifecycle');
    $stmt=$pdo->prepare('SELECT author_id,note_text FROM case_notes WHERE id=?');$stmt->execute([$first['note_id']]);$note=$stmt->fetch(PDO::FETCH_ASSOC);
    severityCheck((int)$note['author_id']===$admin && str_ends_with($note['note_text'],$reason),'full Unicode reason preserved with database author');
    $stmt=$pdo->prepare("SELECT actor_name,details FROM incident_timeline WHERE incident_id=? AND event_type='SEVERITY_CHANGE'");$stmt->execute([$id]);$timeline=$stmt->fetch(PDO::FETCH_ASSOC);
    $stmt=$pdo->prepare("SELECT analyst,details FROM audit_log WHERE target=? AND action='change_incident_severity'");$stmt->execute(['incident:'.$id]);$audit=$stmt->fetch(PDO::FETCH_ASSOC);
    severityCheck($timeline['actor_name']===$name.'-admin' && $audit['analyst']===$name.'-admin' && json_decode($timeline['details'],true)===json_decode($audit['details'],true),'timeline and audit agree and ignore claimed actor');
    $retry=$service->change($auth,$id,'HIGH','MEDIUM','P3','Retry');severityCheck(!$retry['changed'] && severityState($pdo,$id)===$state,'same severity retry preserves timestamps and all history');
    $pdo->prepare("UPDATE incidents SET priority='P1' WHERE id=?")->execute([$id]);$state=severityState($pdo,$id);
    $retry=$service->change($auth,$id,'HIGH','MEDIUM','P3','Retry after risk update');severityCheck(!$retry['changed'] && severityState($pdo,$id)===$state,'same-severity retry does not overwrite a later risk-derived priority');
    foreach ([['LOW','HIGH','P2'],['LOW','MEDIUM','P1']] as [$target,$expected,$priority]) {
        $conflict=false;try{$service->change($auth,$id,$target,$expected,$priority,'Stale review');}catch(IncidentSeverityConflict $e){$conflict=true;}
        severityCheck($conflict && severityState($pdo,$id)===$state && $pdo->inTransaction(),'stale severity or priority conflicts preserve caller transaction and state');
    }
    foreach ([$analyst,$reader,2147483647] as $uid) {
        $denied=false;try{$service->change(['auth_method'=>'session','user_id'=>$uid,'tier'=>'ADMIN'],$id,'HIGH','HIGH','P1','Denied retry');}catch(DomainException $e){$denied=true;}
        severityCheck($denied,'current role and existing user required even for no-op retry');
    }
    foreach ([['auth_method'=>'bearer','user_id'=>$admin],['auth_method'=>'session','user_id'=>null]] as $bad) {
        $denied=false;try{$service->change($bad,$id,'LOW','HIGH','P1','Denied');}catch(DomainException $e){$denied=true;}severityCheck($denied,'bearer and unnamed sessions denied');
    }
    foreach ([['BAD','HIGH','P1','Reason'],['LOW','BAD','P1','Reason'],['LOW','HIGH','P9','Reason'],['LOW','HIGH','P1',' '],['LOW','HIGH','P1',str_repeat('x',2001)],['LOW','HIGH','P1',"\xff"]] as $bad) {
        $invalid=false;try{$service->change($auth,$id,...$bad);}catch(InvalidArgumentException $e){$invalid=true;}severityCheck($invalid,'invalid assessment input rejected');
    }
    $missing=false;try{$service->change($auth,2147483647,'LOW','HIGH','P1','Reason');}catch(OutOfBoundsException $e){$missing=true;}severityCheck($missing,'missing case returns explicit not-found');
    // Fail after update/note/timeline writes; all must roll back to the caller savepoint.
    $pdo->exec('CREATE TEMPORARY TABLE audit_log (unrelated INT)');$failed=false;
    try{$service->change($auth,$id,'LOW','HIGH','P1','Audit write fails');}catch(PDOException $e){$failed=true;}
    $pdo->exec('DROP TEMPORARY TABLE audit_log');
    severityCheck($failed && $pdo->inTransaction() && severityState($pdo,$id)===$state,'audit failure rolls back severity, priority, note and timeline atomically');
    $leadAuth=['auth_method'=>'session','user_id'=>$lead,'tier'=>'TIER1'];
    $changed=$service->change($leadAuth,$id,'LOW','HIGH','P1','Lead reassessment');severityCheck($changed['incident']['priority']==='P4','current lead can lower severity with a reason');
    $sim=$manager->createIncident(['title'=>$name.'-simulation','is_simulated'=>true]);
    $result=$service->change($auth,(int)$sim['id'],'CRITICAL','MEDIUM','P3','Training assessment');severityCheck((int)$result['incident']['is_simulated']===1 && $result['incident']['priority']==='P1','simulation label retained');
    $pdo->prepare("UPDATE incidents SET status='CLOSED' WHERE id=?")->execute([$id]);$state=severityState($pdo,$id);
    $closed=false;try{$service->change($auth,$id,'LOW','LOW','P4','Closed retry');}catch(IncidentSeverityConflict $e){$closed=true;}
    severityCheck($closed && severityState($pdo,$id)===$state,'closed case immutable including no-op requests');
    $pdo->rollBack();
    // Verify committed role downgrade defeats an older caller snapshot.
    $uid=auditUser($pdo,$name.'-current','admin');$case=$manager->createIncident(['title'=>$name.'-current']);$id=(int)$case['id'];$auth=['auth_method'=>'session','user_id'=>$uid,'tier'=>'ADMIN'];
    $pdo->beginTransaction();$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    $other=new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4",$db_user,$db_pass,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $other->prepare("UPDATE users SET role='user' WHERE id=?")->execute([$uid]);
    $denied=false;try{$service->change($auth,$id,'HIGH','MEDIUM','P3','Stale role');}catch(DomainException $e){$denied=true;}
    severityCheck($denied && $pdo->inTransaction(),'current role downgrade enforced inside old snapshot');$pdo->rollBack();
    $pdo->prepare("UPDATE users SET role='admin' WHERE id=?")->execute([$uid]);
    $service->change($auth,$id,'INFO','MEDIUM','P3','Owned transaction');severityCheck(!$pdo->inTransaction() && severityState($pdo,$id)['priority']==='P4','owned successful transaction closes');
    $state=severityState($pdo,$id);$pdo->exec('CREATE TEMPORARY TABLE audit_log (unrelated INT)');$failed=false;
    try{$service->change($auth,$id,'HIGH','INFO','P4','Owned failure');}catch(PDOException $e){$failed=true;}$pdo->exec('DROP TEMPORARY TABLE audit_log');
    severityCheck($failed && !$pdo->inTransaction() && severityState($pdo,$id)===$state,'owned failure rolls back and closes transaction');
    echo "Incident severity integration passed.\n";
} catch (Throwable $e) {
    $pdo->exec('DROP TEMPORARY TABLE IF EXISTS audit_log');if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);
}
