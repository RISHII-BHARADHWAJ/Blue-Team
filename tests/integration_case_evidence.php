<?php
declare(strict_types=1);
require_once __DIR__.'/event_escalation_fixtures.php';
require_once __DIR__.'/../includes/soar/IncidentEvidenceWorkspace.php';
function attachmentCheck(bool $ok,string $message):void{if(!$ok)throw new RuntimeException('FAIL: '.$message);echo "PASS: $message\n";}
$pdo->beginTransaction();
try{
    $name='attach-'.bin2hex(random_bytes(5));$uid=escalationUser($pdo,$name);$reader=escalationUser($pdo,$name.'-reader','user');
    $auth=['auth_method'=>'session','user_id'=>$uid,'actor'=>'FORGED_ACTOR','tier'=>'TIER1'];
    $manager=new IncidentManager($pdo);$repo=new IncidentRepository($pdo);$workspace=new IncidentEvidenceWorkspace($pdo);
    $case=$manager->createIncident(['title'=>$name,'severity'=>'LOW']);$id=(int)$case['id'];
    $other=$manager->createIncident(['title'=>$name.' other']);$otherId=(int)$other['id'];
    $simulation=$manager->createIncident(['title'=>$name.' simulation','is_simulated'=>true]);
    $logs=[];for($i=0;$i<27;$i++)$logs[]=escalationFixture($pdo,$name.'-'.$i);
    $simLog=escalationFixture($pdo,$name.'-sim',true);$legacy=escalationFixture($pdo,$name.'-legacy',false,true);
    $search=$workspace->view($id,['q'=>$name],999);
    attachmentCheck($search['events']['total']===27 && $search['events']['page']===2 && count($search['events']['rows'])===2,'picker excludes simulation/legacy logs and clamps bounded pagination');
    attachmentCheck($workspace->view($id,['q'=>$name,'source_ip'=>'192.0.2.200'])['events']['total']===0,'exact source IP combines with text search');
    $before=$repo->find($id);
    foreach([['auth_method'=>'bearer','user_id'=>$uid],['auth_method'=>'session','user_id'=>null],['auth_method'=>'session','user_id'=>$reader,'tier'=>'ADMIN'],['auth_method'=>'session','user_id'=>2147483647]] as $bad){
        $denied=false;try{$workspace->attach($id,$logs[0],$bad,'Reason');}catch(DomainException $e){$denied=true;}attachmentCheck($denied,'mutations require a named current database analyst');
    }
    foreach([[$id,$simLog],[$id,$legacy],[2147483647,$logs[0]],[(int)$simulation['id'],$logs[0]]] as [$badCase,$badLog]){
        $denied=false;try{$workspace->attach($badCase,$badLog,$auth,'Reason');}catch(InvalidArgumentException|OutOfBoundsException $e){$denied=true;}attachmentCheck($denied,'invalid case or non-real preserved evidence cannot be attached');
    }
    foreach(['',str_repeat('x',10001),"\xff"] as $reason){$bad=false;try{$workspace->attach($id,$logs[0],$auth,$reason);}catch(InvalidArgumentException $e){$bad=true;}attachmentCheck($bad,'invalid rationale is rejected');}
    $repo->attachAlert($otherId,$logs[0],'ORIGINAL_OTHER_CASE_RULE');
    $result=$workspace->attach($id,$logs[0],$auth,'Reason <script>rationale()</script>');
    $notes=(new CaseNoteService($pdo))->list($id);
    attachmentCheck($result['added'] && $notes['total']===1 && (int)$notes['notes'][0]['author_id']===$uid && $notes['notes'][0]['author']===$name,'attachment rationale is preserved and attributed to the database identity');
    attachmentCheck($repo->find($id)===$before,'manual evidence association leaves case severity, priority, risk, status and timestamp unchanged');
    $review=$workspace->view($id,['q'=>$name],1,$logs[0]);
    attachmentCheck($review['selected']['linked_to_case'] && $review['selected']['case_count']===2,'review discloses associations with multiple cases');
    $stmt=$pdo->prepare('SELECT correlation_rule FROM incident_alerts WHERE incident_id=? AND log_id=?');$stmt->execute([$otherId,$logs[0]]);
    attachmentCheck($stmt->fetchColumn()==='ORIGINAL_OTHER_CASE_RULE','linking to this case preserves the other case association');
    $audit=$pdo->prepare("SELECT analyst,details FROM audit_log WHERE action='attach_event_evidence' AND target=?");$audit->execute(['incident:'.$id]);$saved=$audit->fetch();$details=json_decode($saved['details'],true);
    attachmentCheck($saved['analyst']===$name && $details['log_id']===$logs[0] && $details['note_id']===(int)$notes['notes'][0]['id'],'audit connects the event, case, author and rationale');
    $timeline=(new IncidentTimeline($pdo))->getEvents($id);
    $repeat=$workspace->attach($id,$logs[0],$auth,'Different retry reason');
    attachmentCheck(!$repeat['added'] && (new CaseNoteService($pdo))->list($id)['total']===1 && (new IncidentTimeline($pdo))->getEvents($id)===$timeline,'retry adds no note or timeline entry');
    $repo->attachAlert($id,$logs[1],'AUTOMATIC_ORIGINAL');$workspace->attach($id,$logs[1],$auth,'Do not replace provenance');$stmt->execute([$id,$logs[1]]);
    attachmentCheck($stmt->fetchColumn()==='AUTOMATIC_ORIGINAL','pre-existing automatic linkage retains its original provenance');
    $pdo->prepare("UPDATE incidents SET status='CLOSED' WHERE id=?")->execute([$id]);
    attachmentCheck(!$workspace->attach($id,$logs[0],$auth,'Replay after close')['added'],'replay of an existing link leaves a closed case unchanged');
    $conflict=false;try{$workspace->attach($id,$logs[2],$auth,'New link after close');}catch(IncidentEvidenceConflict $e){$conflict=true;}attachmentCheck($conflict,'new attachment is rejected if case closed after review');
    $pdo->exec('CREATE TEMPORARY TABLE audit_log (unrelated INT)');$failed=false;
    try{$workspace->attach($otherId,$logs[2],$auth,'Rollback reason');}catch(PDOException $e){$failed=true;}
    $pdo->exec('DROP TEMPORARY TABLE audit_log');$stmt->execute([$otherId,$logs[2]]);
    attachmentCheck($failed && $pdo->inTransaction() && $stmt->fetchColumn()===false && (new CaseNoteService($pdo))->list($otherId)['total']===0,'audit failure rolls back attachment and note while retaining caller transaction');
    $pdo->prepare("UPDATE users SET role='user' WHERE id=?")->execute([$uid]);$denied=false;
    try{$workspace->attach($otherId,$logs[3],$auth,'Role changed');}catch(DomainException $e){$denied=true;}
    attachmentCheck($denied,'role downgrade is enforced on submission');
    $pdo->rollBack();echo "Case evidence integration passed; fixtures rolled back.\n";
}catch(Throwable $e){$pdo->exec('DROP TEMPORARY TABLE IF EXISTS audit_log');if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
