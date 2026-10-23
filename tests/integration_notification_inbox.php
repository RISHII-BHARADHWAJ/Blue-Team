<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'||getenv('SOAR_INTEGRATION_TEST')!=='1'||getenv('DB_HOST')!=='db')exit(2);
require_once __DIR__.'/../includes/db.php';
require_once __DIR__.'/../includes/soar/notifications/NotificationService.php';
require_once __DIR__.'/../includes/soar/IncidentManager.php';
require_once __DIR__.'/../includes/soar/playbooks/ActionRegistry.php';
require_once __DIR__.'/../includes/soar/playbooks/PlaybookRepository.php';
function inboxCheck(bool $ok,string $message):void{if(!$ok)throw new RuntimeException('FAIL: '.$message);echo "PASS: $message\n";}
$pdo->beginTransaction();
try{
    $name='inbox-ci-'.bin2hex(random_bytes(6));$users=[];
    foreach(['a','b'] as $suffix){$pdo->prepare('INSERT INTO users (username,password,role) VALUES (?,?,?)')->execute([$name.$suffix,'not-a-login-hash','admin']);$users[]=(int)$pdo->lastInsertId();}
    [$a,$b]=$users;$auth=['auth_method'=>'session','user_id'=>$a,'tier'=>'ADMIN'];$authB=['auth_method'=>'session','user_id'=>$b,'tier'=>'ADMIN'];
    $service=new NotificationService($pdo);$case=(new IncidentManager($pdo))->createIncident(['title'=>$name,'is_simulated'=>true]);$id=(int)$case['id'];
    inboxCheck($service->notify($a,'PLAYBOOK_COMPLETED','Done <script>probe()</script>','token: DO_NOT_SHOW',['incident_id'=>$id]),'in-app channel saves notifications with legacy and current schema columns');
    $own=(int)$pdo->lastInsertId();
    $pdo->prepare("INSERT INTO notifications (user_id,recipient_id,title,message,notification_type) VALUES (?,?,?,?, 'INCIDENT_ASSIGNED')")->execute([$a,$b,'OTHER_USER_MESSAGE','password: LEGACY_SECRET']);$foreign=(int)$pdo->lastInsertId();
    $view=$service->inbox($auth,'all');
    inboxCheck($view['pagination']['total']===1 && $view['unread_count']===1 && (int)$view['notifications'][0]['id']===$own,'legacy user_id alias cannot leak another recipient message or unread count');
    inboxCheck((int)$view['notifications'][0]['is_simulated']===1 && !str_contains($view['notifications'][0]['message'],'DO_NOT_SHOW'),'case simulation labels and read-time secret redaction are present');
    $legacy=$service->inbox($authB,'all')['notifications'][0];
    inboxCheck((int)$legacy['id']===$foreign && $legacy['type']==='INCIDENT_ASSIGNED' && !str_contains($legacy['message'],'LEGACY_SECRET'),'legacy notifications reach their actual recipient with corrected type and redacted message');
    $denied=false;try{$service->getUserNotifications($b,$auth);}catch(DomainException $e){$denied=true;}
    inboxCheck($denied,'administrator has no personal-inbox impersonation override');
    foreach([['auth_method'=>'bearer','user_id'=>null],['auth_method'=>'session','user_id'=>null],['auth_method'=>'session','user_id'=>2147483647]] as $invalid){$denied=false;try{$service->inbox($invalid);}catch(DomainException $e){$denied=true;}inboxCheck($denied,'named database identity required for inbox');}
    $failed=false;try{$service->markReadBatch([$own,$foreign],$auth);}catch(OutOfBoundsException $e){$failed=true;}
    inboxCheck($failed && $pdo->inTransaction() && $service->getUnreadCount($a)===1 && $service->getUnreadCount($b)===1,'mixed-owner batch fails atomically and preserves caller transaction');
    inboxCheck(!$service->markAsRead($foreign,$a),'single acknowledgement cannot use the legacy user_id alias');
    inboxCheck($service->markReadBatch([$own,$own],$auth)===1,'duplicate submitted IDs acknowledge once');
    $readAt=$pdo->query('SELECT read_at FROM notifications WHERE id='.$own)->fetchColumn();
    $pdo->prepare("UPDATE notifications SET read_at='2001-01-01 00:00:00' WHERE id=?")->execute([$own]);
    inboxCheck($readAt!==null && $service->markReadBatch([$own],$auth)===0 && $pdo->query('SELECT read_at FROM notifications WHERE id='.$own)->fetchColumn()==='2001-01-01 00:00:00','retry is successful and preserves first read timestamp');
    for($i=0;$i<27;$i++)$service->notify($a,'PLAYBOOK_FAILED','Unread '.$i,'fixture');
    $page=$service->inbox($auth,'unread');$selectedIds=array_column($page['notifications'],'id');
    $service->notify($a,'PLAYBOOK_COMPLETED','Arrived after selection','fixture');$arrival=(int)$pdo->lastInsertId();
    inboxCheck($service->markReadBatch($selectedIds,$auth)===25 && $service->getUnreadCount($a)===3,'bulk action acknowledges only selected page and leaves later arrivals unread');
    $last=$service->inbox($auth,'read',9999);inboxCheck($last['pagination']['page']===$last['pagination']['pages'] && count($last['notifications'])===1,'read filter pagination clamps and remains bounded');
    $unread=$service->inbox($auth,'unread');inboxCheck((int)$unread['notifications'][0]['id']===$arrival,'newest ID resolves same-second ordering');
    $bad=false;try{$service->markReadBatch(array_fill(0,26,$own),$auth);}catch(InvalidArgumentException $e){$bad=true;}inboxCheck($bad,'oversized batches are rejected');
    // Verify normal notification action writes through the channel and dry-run stays side-effect free.
    $real=(new IncidentManager($pdo))->createIncident(['title'=>'Real notification case']);$realId=(int)$real['id'];
    $pbRepo=new PlaybookRepository($pdo);$pb=$pbRepo->createPlaybook(['playbook_name'=>$name,'display_name'=>'Inbox fixture','category'=>'NOTIFICATION'],$a);
    $run=$pbRepo->createRun($pb,$realId,'ANALYST',$a,$name,['mode'=>'MANUAL'],1);
    $context=['incident'=>['id'=>$realId],'analyst'=>['id'=>$a],'playbook_run'=>['id'=>$run]];
    $before=$service->getUnreadCount($a);$action=new NotifyAnalystAction($pdo);
    $preview=$action->execute(['message'=>'token: ACTION_SECRET'],$context,true);
    inboxCheck($preview->status==='SUCCESS' && $service->getUnreadCount($a)===$before,'notification dry-run does not send or save a message');
    $live=$action->execute(['message'=>'token: ACTION_SECRET'],$context,false);$created=(int)$live->data['notification_id'];
    $items=$service->inbox($auth,'unread')['notifications'];$found=array_column($items,null,'id')[$created];
    inboxCheck($live->status==='SUCCESS' && (int)$found['playbook_run_id']===$run && $found['type']==='PLAYBOOK_NOTIFICATION' && !str_contains($found['message'],'ACTION_SECRET'),'notification action persists run link, type and redacted content');
    $pdo->prepare('UPDATE notifications SET playbook_run_id=? WHERE id=?')->execute([$run,$own]);
    $items=$service->inbox($auth,'read',1,100)['notifications'];$found=array_column($items,null,'id')[$own];
    inboxCheck($found['playbook_run_id']===null,'cross-case context cannot produce a misleading run link');
    $pdo->rollBack();echo "Notification inbox integration passed; fixtures rolled back.\n";
}catch(Throwable $e){if($pdo->inTransaction())$pdo->rollBack();fwrite(STDERR,$e->getMessage()."\n");exit(1);}
