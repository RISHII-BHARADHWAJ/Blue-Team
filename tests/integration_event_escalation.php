<?php
declare(strict_types=1);
require_once __DIR__.'/event_escalation_fixtures.php';
function escalationCheck(bool $ok,string $message): void {
    if (!$ok) throw new RuntimeException('FAIL: '.$message);
    echo "PASS: $message\n";
}
$pdo->beginTransaction();
try {
    $name='escalate-'.bin2hex(random_bytes(6));$service=new EventEscalationService($pdo);
    $uid=escalationUser($pdo,$name);$reader=escalationUser($pdo,$name.'-reader','user');
    $auth=['auth_method'=>'session','user_id'=>$uid,'actor'=>'FORGED_DISPLAY','tier'=>'TIER1'];
    $id=escalationFixture($pdo,$name);$sim=escalationFixture($pdo,$name.'sim',true);$legacy=escalationFixture($pdo,$name.'legacy',false,true);
    $before=(int)$pdo->query('SELECT COUNT(*) FROM incidents')->fetchColumn();
    $preview=$service->preview($id,$auth);
    escalationCheck($preview['canonical']['severity']==='MEDIUM' && (int)$pdo->query('SELECT COUNT(*) FROM incidents')->fetchColumn()===$before,'review uses saved canonical severity and creates nothing');
    foreach ([['auth_method'=>'bearer','user_id'=>$uid],['auth_method'=>'session','user_id'=>null],['auth_method'=>'session','user_id'=>2147483647],['auth_method'=>'session','user_id'=>$reader,'tier'=>'ADMIN']] as $bad) {
        $denied=false;try{$service->escalate($id,$bad,'Title','Reason');}catch(DomainException $e){$denied=true;}
        escalationCheck($denied,'named current database analyst required, regardless of claimed tier');
    }
    foreach ([$sim,$legacy,2147483647] as $badId) {
        $denied=false;try{$service->escalate($badId,$auth,'Title','Reason');}catch(InvalidArgumentException|OutOfBoundsException $e){$denied=true;}
        escalationCheck($denied,'simulation, legacy or missing evidence cannot create a real case');
    }
    foreach ([['','Reason'],['Title','   '],[str_repeat('x',256),'Reason'],['Title',str_repeat('x',10001)],["\xff",'Reason']] as [$title,$reason]) {
        $denied=false;try{$service->escalate($id,$auth,$title,$reason);}catch(InvalidArgumentException $e){$denied=true;}
        escalationCheck($denied,'blank, oversized or invalid UTF-8 input is rejected');
    }
    $result=$service->escalate($id,$auth,'Investigate <b>event</b>',"Reason <script>reasonProbe()</script>\nPreserve evidence.");$caseId=$result['incident_id'];
    $case=(new IncidentRepository($pdo))->find($caseId);
    escalationCheck($result['created'] && $case['status']==='NEW' && $case['severity']==='MEDIUM' && $case['priority']==='P3' && $case['assigned_to']===null,'escalation creates a NEW unassigned case with saved severity and derived priority');
    $notes=(new CaseNoteService($pdo))->list($caseId);
    escalationCheck($notes['total']===1 && (int)$notes['notes'][0]['author_id']===$uid && $notes['notes'][0]['author']===$name,'investigation reason is attributed to the database account');
    $stmt=$pdo->prepare("SELECT details,analyst FROM audit_log WHERE action='escalate_event' AND target=?");$stmt->execute(['incident:'.$caseId]);$audit=$stmt->fetch();
    escalationCheck($audit['analyst']===$name && json_decode($audit['details'],true)['log_id']===$id,'audit links evidence, reason and verified actor');
    $stmt=$pdo->prepare('SELECT correlation_rule FROM incident_alerts WHERE incident_id=? AND log_id=?');$stmt->execute([$caseId,$id]);
    escalationCheck($stmt->fetchColumn()==='ANALYST_EVIDENCE_ESCALATION','preserved event is attached as initial evidence');
    $repeat=$service->escalate($id,$auth,'Different retry title','Different retry reason');
    escalationCheck(!$repeat['created'] && $repeat['incident_id']===$caseId && (new CaseNoteService($pdo))->list($caseId)['total']===1,'retry reuses case without changing title or duplicating rationale');
    $pdo->prepare("UPDATE incidents SET status='CLOSED' WHERE id=?")->execute([$caseId]);
    $repeat=$service->escalate($id,$auth,'Retry after closure','Reason');
    escalationCheck(!$repeat['created'] && $repeat['incident_id']===$caseId && (new IncidentRepository($pdo))->find($caseId)['status']==='CLOSED','closed case stays closed and does not create another case on replay');
    $stmt=$pdo->prepare('SELECT COUNT(*) FROM playbook_runs WHERE incident_id=?');$stmt->execute([$caseId]);
    escalationCheck((int)$stmt->fetchColumn()===0,'escalation never starts a playbook');
    $failedId=escalationFixture($pdo,$name.'rollback');$count=(int)$pdo->query('SELECT COUNT(*) FROM incidents')->fetchColumn();
    $pdo->exec('CREATE TEMPORARY TABLE audit_log (unrelated INT)');
    $failed=false;try{$service->escalate($failedId,$auth,'Rollback title','Rollback reason');}catch(PDOException $e){$failed=true;}
    $pdo->exec('DROP TEMPORARY TABLE audit_log');
    $stmt=$pdo->prepare('SELECT COUNT(*) FROM incident_alerts WHERE log_id=?');$stmt->execute([$failedId]);
    escalationCheck($failed && $pdo->inTransaction() && (int)$stmt->fetchColumn()===0 && (int)$pdo->query('SELECT COUNT(*) FROM incidents')->fetchColumn()===$count,'audit failure rolls back new case and evidence link while preserving outer transaction');
    $pdo->prepare("UPDATE users SET role='user' WHERE id=?")->execute([$uid]);
    $denied=false;try{$service->escalate($failedId,$auth,'Title','Reason');}catch(DomainException $e){$denied=true;}
    escalationCheck($denied,'role downgrade takes effect on the next submission');
    $pdo->rollBack();echo "Event escalation integration passed; fixtures rolled back.\n";
} catch(Throwable $e) {
    $pdo->exec('DROP TEMPORARY TABLE IF EXISTS audit_log');
    if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);
}
