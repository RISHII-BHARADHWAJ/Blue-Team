<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/soar/SoarCsrf.php';
require_once __DIR__.'/includes/soar/EventEscalationService.php';
$auth=SoarAuth::getContext($pdo);
if ($auth['actor']==='anonymous') { header('Location: login.php');exit; }
header('Cache-Control: no-store');header('X-Frame-Options: DENY');header('X-Content-Type-Options: nosniff');header('Referrer-Policy: same-origin');
header_remove('X-Powered-By');
function escalationEscape(mixed $v): string { return htmlspecialchars((string)($v??''),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
$method=$_SERVER['REQUEST_METHOD'];
if (!in_array($method,['GET','POST'],true)) { http_response_code(405);header('Allow: GET, POST');exit('Method not allowed.'); }
$service=new EventEscalationService($pdo);$event=null;$error=null;$title='';$reason='';$logId=0;
try {
    $service->actor($auth);
    require_once __DIR__.'/includes/security.php';
    if ($method==='POST') {
        SoarCsrf::enforce($auth);
        if (array_diff(array_keys($_POST),['log_id','title','reason','csrf_token'])) throw new InvalidArgumentException('Unexpected form fields.');
        if (!is_string($_POST['title']??null) || !is_string($_POST['reason']??null)) throw new InvalidArgumentException('Provide a case title and investigation reason.');
        $title=$_POST['title'];$reason=$_POST['reason'];
    }
    $input=$method==='POST'?$_POST:$_GET;
    $logId=filter_var($input['log_id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]) ?: 0;
    if (!$logId) throw new InvalidArgumentException('Select a valid event log ID.');
    $event=$service->preview($logId,$auth);
    if ($method==='POST') {
        $result=$service->escalate($logId,$auth,$title,$reason);
        header('Location: incidents.php?id='.$result['incident_id'],true,303);exit;
    }
    $title='Investigate event #'.$logId;
} catch (DomainException $e) { http_response_code(403);$error=$e->getMessage(); }
catch (OutOfBoundsException $e) { http_response_code(404);$error=$e->getMessage(); }
catch (InvalidArgumentException $e) { http_response_code(422);$error=$e->getMessage(); }
catch (Throwable $e) { http_response_code(503);error_log('Event escalation failed: '.$e->getMessage());$error='Escalation is unavailable. No partial case was saved by this request. Check database health and retry.'; }
$csrf=$event!==null?generateCSRFToken():'';
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ThreatPulse | Escalate event</title><link rel="stylesheet" href="assets/css/workspace.css"><style>textarea{font:inherit;background:#101b2b;color:var(--text);border:1px solid #41536b;border-radius:6px;padding:10px;width:100%;min-height:150px}textarea:focus-visible{outline:2px solid var(--accent)}.case-form{display:grid;gap:16px;max-width:800px}</style><?php require_once __DIR__.'/includes/ui/shell.php'; tpHead(''); ?>
</head>
<body class="tp-app tp-page-events"><?php tpShell('events',''); ?><div class="workspace"><aside class="sidebar"><a class="brand" href="soc.php">ThreatPulse</a><nav aria-label="SOC navigation"><a href="events.php">Event evidence</a><a href="incidents.php">Incidents</a><a href="demo.php">Simulated walkthrough</a></nav></aside><main>
<span class="eyebrow">Evidence / analyst escalation</span><h1>Open an investigation case</h1>
<p>Review the preserved event and record why it needs investigation. Creating a case does not confirm an attack or run a response action.</p>
<?php if ($error): ?><div class="notice error" role="alert"><?= escalationEscape($error) ?></div><?php endif; ?>
<?php if ($event): ?>
<section class="panel"><h2>Event #<?= $logId ?></h2><dl class="facts">
<?php foreach (['Claimed source'=>$event['source'],'Authenticated submitter'=>$event['submitted_by'],'Received (UTC)'=>$event['received_at'],'Saved severity'=>$event['canonical']['severity'],'Saved category'=>$event['canonical']['category']??'Other'] as $label=>$value): ?><div><dt><?= escalationEscape($label) ?></dt><dd><?= escalationEscape($value) ?></dd></div><?php endforeach; ?></dl>
<pre><?= escalationEscape($event['message']) ?><?= $event['message_truncated']?'…':'' ?></pre><a href="events.php?kind=observed&amp;log_id=<?= $logId ?>#evidence">Inspect full preserved evidence</a>
</section>
<?php if ($event['incidents']): ?>
<section class="panel"><h2>Already linked to a case</h2><p>Continue the existing investigation. This workflow does not create another case or reopen a resolved case.</p>
<?php foreach ($event['incidents'] as $case): ?><p><a href="incidents.php?id=<?= (int)$case['id'] ?>"><?= escalationEscape($case['incident_number']) ?></a> · <?= escalationEscape($case['status']) ?></p><?php endforeach; ?></section>
<?php else: ?>
<section class="panel"><h2>Investigation details</h2>
<p>The case starts as NEW and unassigned, with severity and priority derived from the saved event. Your reason is saved as an attributed case note. Repeated submissions through this workspace open the existing case.</p>
<form class="case-form" method="post" action="event-escalate.php">
<input type="hidden" name="csrf_token" value="<?= escalationEscape($csrf) ?>"><input type="hidden" name="log_id" value="<?= $logId ?>">
<div class="field"><label for="title">Case title (up to 255 UTF-8 bytes)</label><input id="title" name="title" required maxlength="255" value="<?= escalationEscape($title) ?>"></div>
<div class="field"><label for="reason">Why does this event need investigation? (up to 10,000 UTF-8 bytes)</label><textarea id="reason" name="reason" required maxlength="10000"><?= escalationEscape($reason) ?></textarea></div>
<div><button type="submit">Create investigation case</button> <a href="events.php?log_id=<?= $logId ?>#evidence">Cancel</a></div>
</form></section>
<?php endif; endif; ?>
</main></div></body></html>
