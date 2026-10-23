<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/soar/SoarCsrf.php';
require_once __DIR__.'/includes/soar/notifications/NotificationService.php';
$auth=SoarAuth::getContext($pdo);
if($auth['actor']==='anonymous'){header('Location: login.php');exit;}
require_once __DIR__.'/includes/security.php';
header('Cache-Control: no-store');header('X-Frame-Options: DENY');
function inboxEscape(mixed $value):string{return htmlspecialchars((string)($value??''),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function inboxUrl(string $filter,int $page=1):string{return 'notifications.php?'.http_build_query(['filter'=>$filter,'page'=>$page]);}
$service=new NotificationService($pdo);$data=null;$error=null;$notice=null;
$filter=$_POST['filter']??$_GET['filter']??'unread';
$page=filter_var($_POST['page']??$_GET['page']??1,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
try{
    $service->resolveUserId($auth);
    if(!is_string($filter)||!in_array($filter,['unread','read','all'],true)||!$page)throw new InvalidArgumentException('Choose a valid inbox filter and page.');
    if($_SERVER['REQUEST_METHOD']==='POST'){
        SoarCsrf::enforce($auth);
        foreach(array_keys($_POST) as $field)if(!in_array($field,['notification_ids','notification_id','filter','page','csrf_token'],true))throw new InvalidArgumentException('Only selected notifications may be acknowledged.');
        if(isset($_POST['notification_ids'],$_POST['notification_id']))throw new InvalidArgumentException('Choose either one notification or a selected batch.');
        $ids=isset($_POST['notification_id'])?[$_POST['notification_id']]:($_POST['notification_ids']??[]);
        if(!is_array($ids))throw new InvalidArgumentException('Select notifications to mark read.');
        $changed=$service->markReadBatch($ids,$auth);
        $_SESSION['inbox_notice']="Marked {$changed} notification(s) read. Already-read items keep their original read time.";
        header('Location: '.inboxUrl($filter,$page),true,303);exit;
    }
    if($_SERVER['REQUEST_METHOD']!=='GET'){header('Allow: GET, POST');http_response_code(405);exit;}
    $data=$service->inbox($auth,$filter,$page,25);
    $notice=$_SESSION['inbox_notice']??null;unset($_SESSION['inbox_notice']);
}catch(DomainException $e){http_response_code(403);$error=$e->getMessage();}
catch(OutOfBoundsException $e){http_response_code(404);$error=$e->getMessage();}
catch(InvalidArgumentException $e){http_response_code(422);$error=$e->getMessage();}
catch(Throwable $e){error_log('Inbox failed: '.$e->getMessage());http_response_code(500);$error='Your inbox is temporarily unavailable.';}
$csrf=$data?generateCSRFToken():'';
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>My inbox · ThreatPulse</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0a1422;color:#e4edf7;font:15px/1.6 system-ui,sans-serif}main{max-width:1060px;margin:auto;padding:28px 22px 60px}nav,.actions,.pager,.top{display:flex;gap:18px;align-items:center;flex-wrap:wrap}.top,.pager{justify-content:space-between}a{color:#76dfd2}h1{font-size:32px;margin-bottom:4px}h2{font-size:20px;margin:6px 0}.muted,small{color:#a9bed3}.notice{color:#ffe1a3}.error{color:#ffb19c}.count{font-size:32px;font-weight:750;color:#76dfd2}.filters{margin:24px 0}.filters a{padding:8px 15px;border:1px solid #38526c;border-radius:6px}.filters a[aria-current=page]{background:#244c49;color:#d2fff7}.notification{border:1px solid #2a425e;border-radius:12px;background:#122033;margin:15px 0;padding:22px}.notification.unread{border-left:4px solid #73dfd0}.message{white-space:pre-wrap;overflow-wrap:anywhere}.pill{font-size:12px;border:1px solid #42617d;border-radius:5px;padding:3px 7px}.actions{margin-top:16px}button{font:inherit;font-weight:700;padding:10px 15px;border:0;border-radius:6px;background:#73dfd0;color:#092129;cursor:pointer}.secondary{background:#29435c;color:#e4edf7}.pager{margin-top:24px}input[type=checkbox]{width:19px;height:19px;vertical-align:middle;margin-right:8px}label{cursor:pointer}small{display:block}form{margin:0}.empty{padding:40px 0;text-align:center}:focus-visible{outline:3px solid #ffd083;outline-offset:3px}
</style></head><body><main><nav><a href="soc.php">SOC overview</a><a href="incidents.php">Incident queue</a><a href="control_plane/index.php">Approval control plane</a></nav>
<h1>My inbox</h1><p class="muted">Saved in-app notifications for your account. Opening a case does not mark a message read or decide an approval.</p>
<?php if($error): ?><p class="error" role="alert"><?= inboxEscape($error) ?></p><a href="notifications.php">Reload inbox</a>
<?php else: $pagination=$data['pagination']; ?>
<div class="top"><div><span class="count"><?= (int)$data['unread_count'] ?></span> unread</div><a href="<?= inboxEscape(inboxUrl($filter,$pagination['page'])) ?>">Refresh inbox</a></div>
<nav class="filters" aria-label="Notification status"><?php foreach(['unread'=>'Unread','all'=>'All','read'=>'Read'] as $value=>$label): ?><a href="<?= inboxEscape(inboxUrl($value)) ?>" <?= $filter===$value?'aria-current="page"':'' ?>><?= $label ?></a><?php endforeach; ?></nav>
<?php if($notice): ?><p class="notice" role="status"><?= inboxEscape($notice) ?></p><?php endif; ?>
<p class="muted"><?= (int)$pagination['total'] ?> matching notifications · newest first · timestamps use server time</p>
<?php $unreadRows=array_filter($data['notifications'],fn($row)=>!$row['is_read']); if($unreadRows): ?><form id="bulk-read" method="post"><input type="hidden" name="csrf_token" value="<?= inboxEscape($csrf) ?>"><input type="hidden" name="filter" value="<?= inboxEscape($filter) ?>"><input type="hidden" name="page" value="<?= (int)$pagination['page'] ?>"><button type="submit">Mark selected read</button><span class="muted"> Select up to 25 messages on this page.</span></form><?php endif; ?>
<?php foreach($data['notifications'] as $row): ?><article class="notification <?= !$row['is_read']?'unread':'' ?>">
<div class="top"><div><?php if(!$row['is_read']): ?><label><input form="bulk-read" type="checkbox" name="notification_ids[]" value="<?= (int)$row['id'] ?>" aria-label="Select notification <?= (int)$row['id'] ?>">Unread</label><?php else: ?><span class="muted">Read<?= $row['read_at']?' · '.inboxEscape($row['read_at']):'' ?></span><?php endif; ?></div><span class="pill"><?= inboxEscape($row['type']) ?></span></div>
<h2><?= inboxEscape($row['title']) ?></h2><div class="message"><?= inboxEscape($row['message']) ?></div><small>#<?= (int)$row['id'] ?> · <?= inboxEscape($row['created_at']) ?></small>
<?php if($row['is_simulated']): ?><p class="notice">SIMULATED TEST DATA</p><?php endif; ?>
<div class="actions"><?php if($row['incident_id']): ?><a href="incidents.php?id=<?= (int)$row['incident_id'] ?>&amp;kind=<?= $row['is_simulated']?'simulated':'observed' ?>#details">Open <?= inboxEscape($row['incident_number']) ?></a><?php endif; ?>
<?php if($row['playbook_run_id']): ?><a href="incident-playbooks.php?id=<?= (int)$row['incident_id'] ?>&amp;run_id=<?= (int)$row['playbook_run_id'] ?>">Inspect run #<?= (int)$row['playbook_run_id'] ?></a><?php endif; ?>
<?php if($row['approval_id']): ?><a href="control_plane/index.php?approval_id=<?= (int)$row['approval_id'] ?>">Inspect approval #<?= (int)$row['approval_id'] ?></a><?php endif; ?>
<?php if(!$row['is_read']): ?><form method="post"><input type="hidden" name="csrf_token" value="<?= inboxEscape($csrf) ?>"><input type="hidden" name="filter" value="<?= inboxEscape($filter) ?>"><input type="hidden" name="page" value="<?= (int)$pagination['page'] ?>"><button class="secondary" name="notification_id" value="<?= (int)$row['id'] ?>" type="submit">Mark read</button></form><?php endif; ?></div></article><?php endforeach; ?>
<?php if(!$data['notifications']): ?><div class="empty"><h2><?= $filter==='unread'?'No unread notifications':'No notifications in this view' ?></h2><p class="muted">New messages from supported workflows appear here when saved for your account.</p><?php if($filter!=='all'): ?><a href="<?= inboxEscape(inboxUrl('all')) ?>">View all notifications</a><?php endif; ?></div><?php endif; ?>
<div class="pager"><span>Page <?= (int)$pagination['page'] ?> of <?= (int)$pagination['pages'] ?></span><span><?php if($pagination['page']>1): ?><a href="<?= inboxEscape(inboxUrl($filter,$pagination['page']-1)) ?>">Newer</a><?php endif; ?> <?php if($pagination['page']<$pagination['pages']): ?><a href="<?= inboxEscape(inboxUrl($filter,$pagination['page']+1)) ?>">Older</a><?php endif; ?></span></div>
<?php endif; ?></main></body></html>
