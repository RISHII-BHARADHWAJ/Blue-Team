<?php
declare(strict_types=1);
require_once __DIR__.'/audit_history_fixtures.php';
require_once __DIR__.'/../includes/soar/ManualCaseService.php';
function intakeCheck(bool $ok,string $message): void {if(!$ok)throw new RuntimeException('FAIL: '.$message);echo "PASS: $message\n";}
function intakeCounts(PDO $pdo): array {
    $out=[];foreach(['incidents','manual_case_requests','case_notes','incident_timeline','audit_log'] as $table)$out[$table]=(int)$pdo->query("SELECT COUNT(*) FROM $table")->fetchColumn();return $out;
}
$service=new ManualCaseService($pdo);$service->available();$pdo->beginTransaction();
try {
    $name='intake-ci-'.bin2hex(random_bytes(5));$analyst=auditUser($pdo,$name.'-analyst','analyst');$reader=auditUser($pdo,$name.'-reader','user');$other=auditUser($pdo,$name.'-lead','lead');
    $auth=['auth_method'=>'session','user_id'=>$analyst,'actor'=>'spoofed','tier'=>'TIER1'];$key=bin2hex(random_bytes(16));$report="Reported by staff; investigate the claimed access.\n日本語 <script>reportProbe()</script>";
    $side=[];foreach(['logs','event_evidence','incident_alerts','playbook_runs','response_actions','notifications','approval_requests'] as $table)$side[$table]=(int)$pdo->query("SELECT COUNT(*) FROM $table")->fetchColumn();
    $first=$service->create($auth,$key,$name,'HIGH',$report);$id=$first['incident_id'];
    $case=(new IncidentRepository($pdo))->find($id);
    intakeCheck($first['created'] && $case['status']==='NEW' && $case['severity']==='HIGH' && $case['priority']==='P2' && $case['assigned_to']===null && (int)$case['risk_score']===0 && (int)$case['is_simulated']===0,'manual intake creates a real unassigned NEW case with severity mapping');
    intakeCheck($case['attack_category']==='Manual report' && str_ends_with($case['description'],$report),'description distinguishes analyst report from sensor evidence');
    $stmt=$pdo->prepare('SELECT author_id,note_text FROM case_notes WHERE incident_id=?');$stmt->execute([$id]);$notes=$stmt->fetchAll(PDO::FETCH_ASSOC);
    intakeCheck(count($notes)===1 && (int)$notes[0]['author_id']===$analyst && $notes[0]['note_text']===$report,'full initial report is attributed to verified account');
    $stmt=$pdo->prepare("SELECT analyst,details FROM audit_log WHERE action='create_manual_case' AND target=?");$stmt->execute(['incident:'.$id]);$audit=$stmt->fetch(PDO::FETCH_ASSOC);
    intakeCheck($audit['analyst']===$name.'-analyst' && json_decode($audit['details'],true)['author_id']===$analyst,'required creation audit ignores claimed actor');
    foreach($side as $table=>$count)intakeCheck((int)$pdo->query("SELECT COUNT(*) FROM $table")->fetchColumn()===$count,"no $table side effects");
    $before=intakeCounts($pdo);$retry=$service->create($auth,$key,' '.$name.' ','HIGH',' '.$report.' ');
    intakeCheck(!$retry['created'] && $retry['incident_id']===$id && intakeCounts($pdo)===$before,'normalized retry preserves all case and history rows');
    foreach([[$name.' changed','HIGH',$report],[$name,'LOW',$report],[$name,'HIGH',$report.' changed']] as $different){
        $conflict=false;try{$service->create($auth,$key,...$different);}catch(ManualCaseConflict $e){$conflict=true;}
        intakeCheck($conflict && intakeCounts($pdo)===$before && $pdo->inTransaction(),'same key with different content conflicts without partial writes');
    }
    $pdo->prepare("UPDATE incidents SET title='Later title',status='CLOSED' WHERE id=?")->execute([$id]);
    intakeCheck($service->create($auth,$key,$name,'HIGH',$report)['incident_id']===$id && (new IncidentRepository($pdo))->find($id)['title']==='Later title','replay returns original case after lifecycle and title changes');
    $second=$service->create(['auth_method'=>'session','user_id'=>$other],$key,$name,'HIGH',$report);
    intakeCheck($second['created'] && $second['incident_id']!==$id,'request keys are scoped per verified user');
    foreach([['auth_method'=>'session','user_id'=>$reader,'tier'=>'ADMIN'],['auth_method'=>'session','user_id'=>2147483647],['auth_method'=>'session'],['auth_method'=>'bearer','user_id'=>$analyst]] as $bad){
        $denied=false;try{$service->create($bad,bin2hex(random_bytes(16)),$name,'HIGH',$report);}catch(DomainException $e){$denied=true;}intakeCheck($denied,'reader, deleted, unnamed and bearer identities denied');
    }
    foreach([['bad',$name,'HIGH',$report],[bin2hex(random_bytes(16)),' ','HIGH',$report],[bin2hex(random_bytes(16)),str_repeat('x',256),'HIGH',$report],[bin2hex(random_bytes(16)),$name,'BAD',$report],[bin2hex(random_bytes(16)),$name,'HIGH',' '],[bin2hex(random_bytes(16)),$name,'HIGH',str_repeat('x',10001)],[bin2hex(random_bytes(16)),$name,'HIGH',"\xff"]] as $bad){
        $invalid=false;try{$service->create($auth,...$bad);}catch(InvalidArgumentException $e){$invalid=true;}intakeCheck($invalid,'invalid intake fields rejected');
    }
    $before=intakeCounts($pdo);$pdo->exec('CREATE TEMPORARY TABLE audit_log (unrelated INT)');$failed=false;
    try{$service->create($auth,bin2hex(random_bytes(16)),$name,'HIGH',$report);}catch(PDOException $e){$failed=true;}$pdo->exec('DROP TEMPORARY TABLE audit_log');
    intakeCheck($failed && $pdo->inTransaction() && intakeCounts($pdo)===$before,'audit failure rolls back request, case, note and timeline inside caller transaction');
    // Force the final request-link update to fail after all case/history writes succeed.
    $pdo->exec('CREATE TEMPORARY TABLE manual_case_requests (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,user_id INT NOT NULL,request_key CHAR(32) NOT NULL,payload_hash CHAR(64) NOT NULL,incident_id BIGINT UNSIGNED NULL CHECK (incident_id IS NULL),UNIQUE KEY(user_id,request_key))');
    $failed=false;try{$service->create($auth,bin2hex(random_bytes(16)),$name,'HIGH',$report);}catch(PDOException $e){$failed=true;}$pdo->exec('DROP TEMPORARY TABLE manual_case_requests');
    intakeCheck($failed && intakeCounts($pdo)===$before,'final mapping failure rolls back the complete creation');
    $pdo->exec('CREATE TEMPORARY TABLE manual_case_requests (unrelated INT)');$missing=false;
    try{$service->available();}catch(PDOException $e){$missing=true;}
    $failed=false;try{$service->create($auth,bin2hex(random_bytes(16)),$name,'HIGH',$report);}catch(PDOException $e){$failed=true;}
    $pdo->exec('DROP TEMPORARY TABLE manual_case_requests');
    intakeCheck($missing && $failed && intakeCounts($pdo)===$before,'missing request storage fails explicitly before any case creation');
    $pdo->rollBack();
    // Current-role authorization also applies to retries in a stale caller snapshot.
    $uid=auditUser($pdo,$name.'-current','admin');$auth=['auth_method'=>'session','user_id'=>$uid,'tier'=>'ADMIN'];$key=bin2hex(random_bytes(16));
    $first=$service->create($auth,$key,$name,'INFO',$report);intakeCheck($first['created'] && !$pdo->inTransaction(),'owned creation commits and closes transaction');
    $before=intakeCounts($pdo);$pdo->beginTransaction();$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    $otherDb=new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4",$db_user,$db_pass,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$otherDb->prepare("UPDATE users SET role='user' WHERE id=?")->execute([$uid]);
    $denied=false;try{$service->create($auth,$key,$name,'INFO',$report);}catch(DomainException $e){$denied=true;}intakeCheck($denied && $pdo->inTransaction(),'role downgrade defeats old snapshot even on existing request');$pdo->rollBack();
    intakeCheck(intakeCounts($pdo)===$before,'denied retry leaves all stored data intact');
    $pdo->prepare("UPDATE users SET role='admin' WHERE id=?")->execute([$uid]);$pdo->exec('CREATE TEMPORARY TABLE audit_log (unrelated INT)');$failed=false;
    try{$service->create($auth,bin2hex(random_bytes(16)),$name,'HIGH',$report);}catch(PDOException $e){$failed=true;}$pdo->exec('DROP TEMPORARY TABLE audit_log');
    intakeCheck($failed && !$pdo->inTransaction() && intakeCounts($pdo)===$before,'owned failure fully rolls back and closes transaction');
    echo "Manual case integration passed.\n";
}catch(Throwable $e){$pdo->exec('DROP TEMPORARY TABLE IF EXISTS audit_log');$pdo->exec('DROP TEMPORARY TABLE IF EXISTS manual_case_requests');if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
