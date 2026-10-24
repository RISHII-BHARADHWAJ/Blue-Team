<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/audit/AuditHistoryService.php';
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') { header('Location: login.php'); exit; }
header('Cache-Control: no-store'); header('X-Frame-Options: DENY'); header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin'); header_remove('X-Powered-By');
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { http_response_code(405); header('Allow: GET'); exit('Method not allowed.'); }
function auditEscape(mixed $value): string { return htmlspecialchars((string)($value ?? ''),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function auditUrl(array $query): string { return 'audit.php?'.http_build_query($query); }
$page = filter_var($_GET['page'] ?? 1,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]) ?: 1;
$view = null; $error = null;
try { $view = (new AuditHistoryService($pdo))->search($auth,$_GET,$page); }
catch (DomainException $e) { http_response_code(403); $error = $e->getMessage(); }
catch (InvalidArgumentException $e) { http_response_code(422); $error = $e->getMessage(); }
catch (OutOfBoundsException $e) { http_response_code(404); $error = $e->getMessage(); }
catch (Throwable $e) { http_response_code(503); error_log('Audit history unavailable: '.$e->getMessage()); $error = 'Audit history is unavailable. Check database health and retry.'; }
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse | Audit history</title><link rel="stylesheet" href="assets/css/workspace.css"><?php require_once __DIR__.'/includes/ui/shell.php'; tpHead(''); ?>
</head>
<body class="tp-app tp-page-audit"><?php tpShell('audit',''); ?><a class="skip" href="#main">Skip to audit history</a><div class="workspace"><aside class="sidebar"><a class="brand" href="soc.php">ThreatPulse</a>
<nav aria-label="SOC navigation"><a href="soc.php">Overview</a><a href="incidents.php">Incidents</a><a href="control_plane/index.php">SOAR approvals</a><a href="audit.php" aria-current="page">Audit history</a></nav></aside>
<main id="main"><span class="eyebrow">Oversight / recorded actions</span><h1>Audit history</h1>
<?php if ($error): ?><div class="notice error" role="alert"><?= auditEscape($error) ?></div><?php endif; ?>
<?php if ($view): $filters = $view['filters']; ?>
<p>Review recorded actors, actions and outcomes. Case links appear when a stored target directly identifies an existing case. Details, command targets and user-agent contents are omitted.</p>
<div class="notice">This is the application's recorded history, not a complete or tamper-proof account of activity. Case filtering covers direct case targets only; approvals and other workflows may record different targets. Use the case timeline and workflow history for additional context.</div>
<?php if ($view['case']): ?><p>Direct references to <a href="incidents.php?id=<?= (int)$view['case']['id'] ?>#details"><?= auditEscape($view['case']['incident_number']) ?></a><?php if ($view['case']['is_simulated']): ?> · <strong>SIMULATED CASE</strong><?php endif; ?></p><?php endif; ?>
<section class="panel" aria-label="Audit filters"><form class="filters" method="get" action="audit.php">
<div class="field wide"><label for="q">Actor or action contains</label><input id="q" name="q" maxlength="200" value="<?= auditEscape($filters['q']) ?>"></div>
<div class="field"><label for="action">Action (exact)</label><input id="action" name="action" maxlength="100" value="<?= auditEscape($filters['action']) ?>"></div>
<div class="field"><label for="result">Recorded outcome</label><select id="result" name="result">
<?php foreach (['all'=>'All outcomes','success'=>'Success','failure'=>'Failure','blocked'=>'Blocked','unknown'=>'Not recorded'] as $value=>$label): ?><option value="<?= $value ?>" <?= $filters['result'] === $value ? 'selected' : '' ?>><?= $label ?></option><?php endforeach; ?></select></div>
<div class="field"><label for="from">From date (server time)</label><input type="date" id="from" name="from" value="<?= auditEscape($filters['from']) ?>"></div>
<div class="field"><label for="to">Through date (server time)</label><input type="date" id="to" name="to" value="<?= auditEscape($filters['to']) ?>"></div>
<div class="field"><label for="case-id">Direct case reference (ID)</label><input type="number" min="1" id="case-id" name="case_id" value="<?= auditEscape($filters['case_id']) ?>"></div>
<div class="field"><label for="sort">Order</label><select id="sort" name="sort"><option value="newest" <?= $filters['sort'] === 'newest' ? 'selected' : '' ?>>Newest first</option><option value="oldest" <?= $filters['sort'] === 'oldest' ? 'selected' : '' ?>>Oldest first</option></select></div>
<button type="submit">Search audit history</button><a href="audit.php">Clear filters</a>
</form></section>
<section class="panel" aria-label="Audit results"><h2>Recorded actions</h2><p><?= (int)$view['total'] ?> matching records · up to 25 per page. Times and date boundaries use database server time.</p>
<div class="table-wrap"><table><thead><tr><th scope="col">Recorded / ID</th><th scope="col">Actor / source IP</th><th scope="col">Action</th><th scope="col">Outcome</th><th scope="col">Case reference</th></tr></thead><tbody>
<?php foreach ($view['rows'] as $row): ?>
<tr data-audit-id="<?= (int)$row['id'] ?>"><td><?= auditEscape($row['timestamp'] ?? 'Time not recorded') ?><br>#<?= (int)$row['id'] ?></td><td class="message"><?= auditEscape($row['analyst'] ?: 'Not recorded') ?><br><?= auditEscape($row['ip_address'] ?: 'Not recorded') ?></td><td class="message"><?= auditEscape($row['action'] ?: 'Not recorded') ?></td><td><span class="badge <?= in_array($row['result'],['failure','blocked'],true) ? 'WARNING' : '' ?>"><?= auditEscape($row['result'] ?? 'Not recorded') ?></span></td><td>
<?php if ($row['case']): ?><a href="incidents.php?id=<?= (int)$row['case']['id'] ?>#details"><?= auditEscape($row['case']['incident_number']) ?></a><?php if ($row['case']['is_simulated']): ?><br><span class="badge simulated">SIMULATED</span><?php endif; ?>
<?php else: ?>No direct case reference<?php endif; ?></td></tr>
<?php endforeach; ?>
<?php if (!$view['rows']): ?><tr><td colspan="5">No audit records match these filters.</td></tr><?php endif; ?>
</tbody></table></div><nav class="pages" aria-label="Audit pagination"><span>Page <?= (int)$view['page'] ?> of <?= (int)$view['pages'] ?></span><div>
<?php if ($view['page'] > 1): ?><a rel="prev" href="<?= auditEscape(auditUrl($filters + ['page'=>$view['page']-1])) ?>">Previous</a><?php endif; ?>
<?php if ($view['page'] < $view['pages']): ?><a rel="next" href="<?= auditEscape(auditUrl($filters + ['page'=>$view['page']+1])) ?>">Next</a><?php endif; ?>
</div></nav></section><?php endif; ?>
</main></div></body></html>
