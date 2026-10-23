<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db')exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
function handoffCheck(bool $ok,string $message): void { if(!$ok)throw new RuntimeException('FAIL: '.$message);echo "PASS: $message\n"; }
$pdo->beginTransaction();
try {
    $name='handoff-'.bin2hex(random_bytes(6));$users=[];
    foreach(['a'=>'analyst','b'=>'analyst','c'=>'user'] as $suffix=>$role) {
        $pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name.$suffix,'not-a-login-hash',$role]);$users[$suffix]=(int)$pdo->lastInsertId();
    }
    $manager=new IncidentManager($pdo);$repo=new IncidentRepository($pdo);
    $case=$manager->createIncident(['title'=>$name,'severity'=>'MEDIUM']);$id=(int)$case['id'];
    $assigned=$manager->assignIncident($id,$users['a'],'token: ASSIGNMENT_SECRET',null);
    $stmt=$pdo->prepare('SELECT * FROM notifications WHERE incident_id=?');$stmt->execute([$id]);$messages=$stmt->fetchAll();
    handoffCheck((int)$assigned['assigned_to']===$users['a'] && count($messages)===1 && (int)$messages[0]['recipient_id']===$users['a'] && (int)$messages[0]['user_id']===$users['a'] && $messages[0]['type']==='INCIDENT_ASSIGNED','assignment and one recipient-owned case notification are saved');
    handoffCheck(!str_contains($messages[0]['message'],'ASSIGNMENT_SECRET'),'assignment message uses shared secret redaction');
    $notificationId=(int)$messages[0]['id'];
    $pdo->prepare("UPDATE incidents SET updated_at='2001-01-01 00:00:00' WHERE id=?")->execute([$id]);
    $before=$manager->getIncident($id);
    $repeated=$manager->assignIncident($id,$users['a'],'retry',null);
    $stmt->execute([$id]);
    handoffCheck($repeated===$before && count($stmt->fetchAll())===1,'same-owner replay preserves case timestamp and does not duplicate timeline or inbox messages');
    $conflict=false;try{$manager->assignIncident($id,$users['b'],'stale page',null);}catch(IncidentAssignmentConflict $e){$conflict=true;}
    handoffCheck($conflict && (int)$repo->find($id)['assigned_to']===$users['a'],'stale expected owner cannot overwrite a different current owner');
    $reassigned=$manager->assignIncident($id,$users['b'],'case-lead',$users['a']);
    $stmt->execute([$id]);$messages=$stmt->fetchAll();
    handoffCheck((int)$reassigned['assigned_to']===$users['b'] && count($messages)===2 && (int)$messages[1]['recipient_id']===$users['b'],'reassignment notifies only the new owner and keeps prior message history');
    $audit=$pdo->prepare("SELECT details FROM audit_log WHERE action='assign_incident' AND target=? ORDER BY id DESC LIMIT 1");$audit->execute([$case['incident_number']]);$details=json_decode($audit->fetchColumn(),true);
    handoffCheck($details['previous_assigned_to']===$users['a'] && $details['assigned_to_user_id']===$users['b'],'audit records previous and next owners');
    $before=$manager->getIncident($id);
    foreach(['notifications','audit_log'] as $table) {
        $pdo->exec("CREATE TEMPORARY TABLE $table (unrelated INT)");$failed=false;
        try{$manager->assignIncident($id,$users['a'],'failing writer',$users['b']);}catch(Throwable $e){$failed=true;}
        $pdo->exec("DROP TEMPORARY TABLE $table");
        handoffCheck($failed && $pdo->inTransaction() && $manager->getIncident($id)===$before,'failed '.$table.' persistence rolls back owner, timestamp and timeline while retaining caller transaction');
    }
    $stmt->execute([$id]);handoffCheck(count($stmt->fetchAll())===2,'failed handoffs leave no extra inbox rows');
    $bad=false;try{$manager->assignIncident($id,$users['c'],'lead',$users['b']);}catch(InvalidArgumentException $e){$bad=true;}
    handoffCheck($bad,'ordinary users remain ineligible assignment targets');
    $simulation=$manager->createIncident(['title'=>$name.' simulation','is_simulated'=>true]);$simId=(int)$simulation['id'];
    $manager->assignIncident($simId,$users['a'],'trainer');
    $stmt->execute([$simId]);$message=$stmt->fetch();
    handoffCheck(str_starts_with($message['title'],'SIMULATED:') && str_starts_with($message['message'],'SIMULATED:'),'training assignment is explicitly labeled');
    $inbox=(new NotificationService($pdo))->inbox(['auth_method'=>'session','user_id'=>$users['a']],'all');
    $byId=array_column($inbox['notifications'],null,'id');
    handoffCheck((int)$byId[$notificationId]['incident_id']===$id && (int)$byId[$message['id']]['is_simulated']===1,'personal inbox exposes real case link and simulation label');
    // Existing three-argument clients continue to assign without a compare-and-set guard.
    $legacy=$manager->assignIncident($id,$users['a'],'legacy-client');
    handoffCheck((int)$legacy['assigned_to']===$users['a'],'existing assignment call contract remains supported');
    $pdo->rollBack();echo "Assignment handoff integration passed; fixtures rolled back.\n";
}catch(Throwable $e){foreach(['notifications','audit_log'] as $table)$pdo->exec("DROP TEMPORARY TABLE IF EXISTS $table");if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
