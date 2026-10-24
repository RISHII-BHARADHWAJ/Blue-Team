<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/ManualCaseService.php';
require_once __DIR__.'/includes/soar/SoarCsrf.php';
$auth=SoarAuth::getContext($pdo);
if ($auth['actor']==='anonymous') {header('Location: login.php');exit;}
header('Cache-Control: no-store');header('X-Frame-Options: DENY');header('X-Content-Type-Options: nosniff');
require_once __DIR__.'/includes/security.php';
function intakeEscape(mixed $value): string {return htmlspecialchars((string)($value??''),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
$method=$_SERVER['REQUEST_METHOD'];
if (!in_array($method,['GET','POST'],true)) {http_response_code(405);header('Allow: GET, POST');exit('Method not allowed.');}
$service=new ManualCaseService($pdo);$error=null;$allowed=false;
$values=['request_key'=>bin2hex(random_bytes(16)),'title'=>'','severity'=>'MEDIUM','report'=>''];
try {
    $service->actor($auth);$allowed=true;
    if ($method==='POST') {
        SoarCsrf::enforce($auth);
        // Preserve valid text fields and the request identity on validation/storage failure.
        foreach ($values as $key=>$default) if (isset($_POST[$key]) && is_string($_POST[$key])) $values[$key]=$_POST[$key];
        if (array_diff(array_keys($_POST),['request_key','title','severity','report','csrf_token'])) throw new InvalidArgumentException('Unexpected form fields. Only case title, severity and report may be submitted.');
        foreach (array_keys($values) as $key) if (!is_string($_POST[$key]??null)) throw new InvalidArgumentException('Complete every intake field using text.');
        $result=$service->create($auth,$values['request_key'],$values['title'],$values['severity'],$values['report']);
        $_SESSION['manual_case_notice']=['id'=>$result['incident_id'],'text'=>$result['created']?'Manual report saved as a new case. Review the report, assign an owner and link supporting evidence.':'This submission already created a case. The existing case and original report were preserved.'];
        header('Location: incidents.php?id='.$result['incident_id'].'&kind=observed#details',true,303);exit;
    }
    $service->available();
} catch (DomainException $e) {http_response_code(403);$allowed=false;$error=$e->getMessage();}
catch (ManualCaseConflict $e) {http_response_code(409);$error=$e->getMessage();}
catch (InvalidArgumentException $e) {http_response_code(422);$error=$e->getMessage();}
catch (Throwable $e) {http_response_code(503);error_log('Manual case intake failed: '.$e->getMessage());$error='Manual intake is unavailable. Check database health and that migration 013 is applied. Your report is retained below; retry the same submission after recovery.';}
$csrf=$allowed?generateCSRFToken():'';
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Report a case · ThreatPulse</title><link rel="stylesheet" href="assets/css/workspace.css"><style>.intake-form{display:grid;gap:18px;max-width:850px}textarea{width:100%;min-height:240px;resize:vertical;font:inherit;padding:12px;border:1px solid #41536b;border-radius:6px;background:#101b2b;color:var(--text)}.intake-form input{width:100%}</style><?php require_once __DIR__.'/includes/ui/shell.php'; tpHead(''); ?>
</head><body class="tp-app tp-page-cases"><?php tpShell('cases',''); ?><div class="workspace"><aside class="sidebar"><a class="brand" href="soc.php">ThreatPulse</a><nav aria-label="SOC navigation"><a href="incidents.php">Incident queue</a><a href="events.php">Event evidence</a><a href="demo.php">Simulated walkthrough</a></nav></aside><main>
<span class="eyebrow">Investigation / manual intake</span><h1>Report a case</h1>
<p>Record a report received outside sensor telemetry, such as an analyst finding or a user report. This creates a real, unassigned case in NEW status with an attributed investigation note. It does not establish that an attack occurred.</p>
<p>No sensor event is fabricated or attached. Risk starts unassessed at 0; no response or playbook runs. If you already have preserved evidence, <a href="events.php">open the event and escalate it</a>. For training, use the <a href="demo.php">simulated walkthrough</a>.</p>
<?php if ($error): ?><div class="notice error" role="alert"><?= intakeEscape($error) ?></div><?php endif; ?>
<?php if ($allowed): ?><section class="panel"><form method="post" action="incident-new.php" class="intake-form">
<input type="hidden" name="csrf_token" value="<?= intakeEscape($csrf) ?>"><input type="hidden" name="request_key" value="<?= intakeEscape($values['request_key']) ?>">
<div class="field"><label for="case-title">Case title · up to 255 UTF-8 bytes</label><input id="case-title" name="title" maxlength="255" required value="<?= intakeEscape($values['title']) ?>"></div>
<div class="field"><label for="case-severity">Initial severity and priority</label><select id="case-severity" name="severity" required><?php foreach (['CRITICAL'=>'P1','HIGH'=>'P2','MEDIUM'=>'P3','LOW'=>'P4','INFO'=>'P4'] as $value=>$priority): ?><option value="<?= $value ?>" <?= $values['severity']===$value?'selected':'' ?>><?= $value ?> → <?= $priority ?></option><?php endforeach; ?></select></div>
<div class="field"><label for="case-report">Report and reason to investigate · up to 10,000 UTF-8 bytes</label><textarea id="case-report" name="report" maxlength="10000" required placeholder="Who reported this, what was observed, when it happened, and what needs investigation?"><?= intakeEscape($values['report']) ?></textarea></div>
<p>Your report is saved with your current account name. Retrying this submission returns the same case. Opening a <a href="incident-new.php">new intake form</a> starts a separate submission; review the <a href="incidents.php">queue</a> first to avoid duplicate reports.</p>
<div><button type="submit">Create case and save report</button></div>
</form></section><?php endif; ?>
</main></div></body></html>
