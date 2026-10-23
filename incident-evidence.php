<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/soar/SoarCsrf.php';require_once __DIR__.'/includes/soar/IncidentEvidenceWorkspace.php';
$auth=SoarAuth::getContext($pdo);
if($auth['actor']==='anonymous'){header('Location: login.php');exit;}
if(!SoarAuth::hasPermission($auth['tier'],'view_incidents')){http_response_code(403);exit('Not authorized to view cases.');}
require_once __DIR__.'/includes/security.php';
header('Cache-Control: no-store');header('X-Frame-Options: DENY');header('X-Content-Type-Options: nosniff');header('Referrer-Policy: same-origin');header_remove('X-Powered-By');
function evidenceEscape(mixed $v):string{return htmlspecialchars((string)($v??''),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function evidenceUrl(array $p):string{return 'incident-evidence.php?'.http_build_query($p);}
$method=$_SERVER['REQUEST_METHOD'];
if(!in_array($method,['GET','POST'],true)){http_response_code(405);header('Allow: GET, POST');exit('Method not allowed.');}
$canAttach=$auth['auth_method']==='session'&&!empty($auth['user_id'])&&SoarAuth::hasPermission($auth['tier'],'attach_alerts');
$input=$method==='POST'?$_POST:$_GET;
$id=filter_var($input['id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]])?:0;
$logId=filter_var($input['log_id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]])?:null;
$page=filter_var($_GET['page']??1,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]])?:1;
$workspace=new IncidentEvidenceWorkspace($pdo);$data=null;$error=null;$reason='';
try{
    if(!$id)throw new InvalidArgumentException('Select a valid incident.');
    if($method==='POST'){
        SoarCsrf::enforce($auth);
        if(array_diff(array_keys($_POST),['id','log_id','reason','csrf_token']))throw new InvalidArgumentException('Unexpected form fields.');
        if(!$logId||!is_string($_POST['reason']??null))throw new InvalidArgumentException('Select an event and provide an investigation reason.');
        $reason=$_POST['reason'];
        $result=$workspace->attach($id,$logId,$auth,$reason);
        $_SESSION['case_evidence_notice']=['id'=>$id,'text'=>$result['added']?'Event linked and investigation reason saved.':'This event was already linked. No duplicate note or link was created.'];
        header('Location: '.evidenceUrl(['id'=>$id,'log_id'=>$logId]),true,303);exit;
    }
    $data=$workspace->view($id,$_GET,$page,$logId);
}catch(IncidentEvidenceConflict $e){http_response_code(409);$error=$e->getMessage();}
catch(DomainException $e){http_response_code(403);$error=$e->getMessage();}
catch(OutOfBoundsException $e){http_response_code(404);$error=$e->getMessage();}
catch(InvalidArgumentException $e){http_response_code(422);$error=$e->getMessage();}
catch(Throwable $e){http_response_code(503);error_log('Case evidence workspace failed: '.$e->getMessage());$error='Case evidence is unavailable. Check database health and retry.';}
if($method==='POST' && http_response_code()===422 && $id && $logId){
    try{$data=$workspace->view($id,[],1,$logId);}catch(Throwable $ignored){}
}
$notice=$_SESSION['case_evidence_notice']??null;unset($_SESSION['case_evidence_notice']);
$csrf=$canAttach?generateCSRFToken():'';
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ThreatPulse | Link case evidence</title><link rel="stylesheet" href="assets/css/workspace.css"><style>textarea{font:inherit;background:#101b2b;color:var(--text);border:1px solid #41536b;border-radius:6px;padding:10px;width:100%;min-height:140px}textarea:focus-visible{outline:2px solid var(--accent)}.attach-form{display:grid;gap:14px;max-width:800px}</style></head>
<body><div class="workspace"><aside class="sidebar"><a class="brand" href="soc.php">ThreatPulse</a><nav aria-label="SOC navigation"><a href="incidents.php">Incidents</a><a href="events.php">Event evidence</a><a href="notifications.php">My inbox</a></nav></aside><main>
<span class="eyebrow">Investigation / evidence association</span><h1>Link preserved event evidence</h1>
<?php if($id): ?><p><a href="incidents.php?id=<?= $id ?>#details">Back to case</a> · <a href="incident-linked-evidence.php?id=<?= $id ?>">Browse linked evidence</a> · <a href="<?= evidenceEscape(evidenceUrl(['id'=>$id])) ?>">Reload evidence picker</a></p><?php endif; ?>
<?php if($error): ?><div class="notice error" role="alert"><?= evidenceEscape($error) ?></div><?php endif; ?>
<?php if($data): $case=$data['incident'];$events=$data['events'];$filters=$data['filters'];$selected=$data['selected'];$query=['id'=>$id,'q'=>$filters['q'],'source_ip'=>$filters['source_ip']];$active=IncidentStateMachine::isActive($case['status']); ?>
<p><?= evidenceEscape($case['incident_number']) ?> · <?= evidenceEscape($case['title']) ?> · <?= evidenceEscape($case['status']) ?></p>
<p>Search real preserved submissions, review an event, and explain its relevance to this case. Linking preserves the original evidence and does not change case severity, priority or risk, discover indicators, or run a response.</p>
<?php if(is_array($notice)&&($notice['id']??null)===$id): ?><div class="notice" role="status"><?= evidenceEscape($notice['text']) ?></div><?php endif; ?>
<?php if(!$active): ?><div class="notice">This case is resolved or closed. You can inspect candidates, but new attachments are disabled.</div><?php endif; ?>
<section class="panel"><form class="filters" method="get" action="incident-evidence.php"><input type="hidden" name="id" value="<?= $id ?>"><div class="field wide"><label for="q">Message or source event ID</label><input id="q" name="q" maxlength="200" value="<?= evidenceEscape($filters['q']) ?>"></div><div class="field"><label for="source-ip">Source IP (exact)</label><input id="source-ip" name="source_ip" maxlength="45" value="<?= evidenceEscape($filters['source_ip']) ?>"></div><button type="submit">Search evidence</button></form></section>
<section class="panel"><h2>Candidate events</h2><p><?= (int)$events['total'] ?> matching real submissions · up to 25 per page. Simulations and legacy logs without preserved provenance are excluded.</p><div class="table-wrap"><table><thead><tr><th>Received (UTC)</th><th>Source / IP</th><th>Message preview</th><th>Case link</th></tr></thead><tbody>
<?php foreach($events['rows'] as $row): ?><tr><td><?= evidenceEscape($row['received_at']) ?></td><td><?= evidenceEscape($row['source']) ?><br><?= evidenceEscape($row['source_ip']) ?></td><td class="message"><?= evidenceEscape(substr($row['message']??'',0,200)) ?><?= strlen($row['message']??'')>200?'…':'' ?></td><td><a href="<?= evidenceEscape(evidenceUrl($query+['page'=>$events['page'],'log_id'=>$row['log_id']])) ?>#selected-event"><?= $row['linked_to_case']?'Already linked · review':'Review event #'.(int)$row['log_id'] ?></a></td></tr><?php endforeach; ?>
<?php if(!$events['rows']): ?><tr><td colspan="4">No matching preserved events.</td></tr><?php endif; ?></tbody></table></div><div class="pages"><span>Page <?= (int)$events['page'] ?> of <?= (int)$events['pages'] ?></span><div><?php if($events['page']>1): ?><a href="<?= evidenceEscape(evidenceUrl($query+['page'=>$events['page']-1])) ?>">Previous</a><?php endif; ?> <?php if($events['page']<$events['pages']): ?><a href="<?= evidenceEscape(evidenceUrl($query+['page'=>$events['page']+1])) ?>">Next</a><?php endif; ?></div></div></section>
<?php if($selected): ?>
<section class="panel" id="selected-event"><h2>Review event #<?= (int)$selected['log_id'] ?></h2><dl class="facts">
<?php foreach(['Claimed source'=>$selected['source'],'Authenticated submitter'=>$selected['submitted_by'],'Received (UTC)'=>$selected['received_at'],'Event time (UTC)'=>$selected['event_timestamp'],'Source IP'=>$selected['source_ip'],'Severity'=>$selected['severity']==='WARNING'?'MEDIUM':$selected['severity']] as $label=>$value): ?><div><dt><?= evidenceEscape($label) ?></dt><dd><?= evidenceEscape($value) ?></dd></div><?php endforeach; ?></dl>
<pre><?= evidenceEscape($selected['message']) ?><?= $selected['message_truncated']?'…':'' ?></pre><p><a href="events.php?kind=observed&amp;log_id=<?= (int)$selected['log_id'] ?>#evidence">Inspect full preserved evidence and linked cases</a></p><p>This event is currently linked to <?= (int)$selected['case_count'] ?> case(s). Linking it here records an additional association, not a move or proof that the cases are the same incident.</p>
<?php if($selected['linked_to_case']): ?><div class="notice">Already linked to this case. Existing provenance and notes are preserved.</div>
<?php elseif($canAttach&&$active): ?>
<form class="attach-form" method="post" action="incident-evidence.php"><input type="hidden" name="id" value="<?= $id ?>"><input type="hidden" name="log_id" value="<?= (int)$selected['log_id'] ?>"><input type="hidden" name="csrf_token" value="<?= evidenceEscape($csrf) ?>"><div class="field"><label for="reason">Why is this event relevant to the case? Up to 10,000 UTF-8 bytes.</label><textarea id="reason" name="reason" maxlength="10000" required><?= evidenceEscape($reason) ?></textarea></div><div><button type="submit">Link event and save reason</button></div></form>
<?php elseif($active): ?><p>A named Tier 2 or higher analyst can link this event.</p><?php endif; ?>
</section><?php endif; endif; ?>
</main></div></body></html>
