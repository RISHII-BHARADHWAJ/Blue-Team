<?php
/** Detection findings and administrator-only typed rule settings. */
declare(strict_types=1);
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/soar/SoarAuth.php';
require_once __DIR__ . '/includes/soar/SoarCsrf.php';
require_once __DIR__ . '/includes/siem/DetectionRepository.php';
$auth = SoarAuth::getContext($pdo);
if ($auth['auth_method'] === 'anonymous') { header('Location: login.php'); exit; }
if (!SoarAuth::hasPermission($auth['tier'], 'view_alerts')) { http_response_code(403); exit('Not authorized.'); }
header('X-Frame-Options: DENY'); header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store'); header('Referrer-Policy: same-origin');
header("Content-Security-Policy: default-src 'self'; style-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
function detectionEscape(mixed $v): string { return htmlspecialchars((string)($v ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
$_SESSION['csrf_token'] ??= bin2hex(random_bytes(32));
$canManage = $auth['auth_method'] === 'session' && !empty($auth['user_id']) && SoarAuth::hasPermission($auth['tier'], 'admin_operations');
$repo = new DetectionRepository($pdo);
$error = null; $rules = []; $detail = null; $result = null;
$kind = is_string($_GET['kind'] ?? null) && in_array($_GET['kind'], ['observed','simulated','all'], true) ? $_GET['kind'] : 'observed';
$page = filter_var($_GET['page'] ?? 1, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: 1;
$id = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: null;
try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!$canManage) { http_response_code(403); exit('Only named administrators can configure rules.'); }
        SoarCsrf::enforce($auth);
        $key = is_string($_POST['rule_key'] ?? null) ? $_POST['rule_key'] : '';
        $repo->updateRule($key, $_POST, (int)$auth['user_id']);
        header('Location: detections.php?saved=1', true, 303); exit;
    }
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') { header('Allow: GET, POST'); http_response_code(405); exit('Method not allowed.'); }
    $rules = $repo->rules(); $result = $repo->findings($kind, $page);
    if ($id) { $detail = $repo->find($id); if (!$detail) { http_response_code(404); $error='Finding not found.'; } }
} catch (UnexpectedValueException $e) { http_response_code(403); $error=$e->getMessage(); }
catch (InvalidArgumentException $e) { http_response_code(422); $error=$e->getMessage(); }
catch (DomainException $e) { http_response_code(409); $error=$e->getMessage(); }
catch (Throwable $e) {
    error_log('Detections workspace failed: ' . $e->getMessage()); http_response_code(503);
    $error='Detection storage is unavailable. Check database health and apply migration 009 using the upgrade instructions.';
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse | Detections</title><link rel="stylesheet" href="assets/css/workspace.css"><?php require_once __DIR__.'/includes/ui/shell.php'; tpHead(''); ?>
</head><body class="tp-app tp-page-detections"><?php tpShell('detections',''); ?>
<a class="skip" href="#main">Skip to detections</a><div class="workspace"><aside class="sidebar">
<a class="brand" href="soc.php">ThreatPulse</a><nav aria-label="SOC navigation"><a href="soc.php">Overview</a><a href="events.php">Event evidence</a><a href="detections.php" aria-current="page">Detections</a><a href="threat-intel.php">Threat intelligence</a><a href="feeds.php">Feed health</a><a href="incidents.php">Incidents</a><a href="control_plane/index.php">SOAR approvals</a></nav>
<p>Evidence-backed findings<br>All times are UTC</p></aside><main id="main"><span class="eyebrow">Investigate / detection rules</span><h1>Detections</h1>
<p>Review rule findings, inspect supporting submissions, and tune detection settings. A finding calls for investigation; it does not confirm compromise.</p>
<?php if ($error): ?><div class="notice error" role="alert"><?= detectionEscape($error) ?> <a href="detections.php">Reload settings</a></div><?php endif; ?>
<?php if (isset($_GET['saved']) && !$error): ?><div class="notice" role="status">Rule settings saved and audited. New events use the updated revision.</div><?php endif; ?>
<?php if ($result): ?>
<section class="panel"><div class="panel-head"><h2>Findings</h2><span><?= detectionEscape($result['total']) ?> matching findings</span></div>
<form method="get" class="filters"><div class="field"><label for="kind">Evidence type</label><select name="kind" id="kind"><?php foreach (['observed'=>'Sensor reported','simulated'=>'Simulated tests','all'=>'All findings'] as $value=>$label): ?><option value="<?= detectionEscape($value) ?>" <?= $kind===$value?'selected':'' ?>><?= detectionEscape($label) ?></option><?php endforeach; ?></select></div><button type="submit">Filter findings</button></form>
<div class="table-wrap"><table><thead><tr><th>Finding / UTC</th><th>Rule / severity</th><th>Evidence type</th><th>Summary</th><th>Incident</th></tr></thead><tbody>
<?php foreach ($result['rows'] as $row): ?><tr><td><a href="detections.php?id=<?= detectionEscape($row['id']) ?>&amp;kind=<?= detectionEscape($kind) ?>#finding">#<?= detectionEscape($row['id']) ?></a><br><?= detectionEscape($row['created_at']) ?></td><td><?= detectionEscape($row['rule_key']) ?><br><span class="badge"><?= detectionEscape($row['severity']) ?></span></td><td><span class="badge <?= $row['is_simulated']?'simulated':'' ?>"><?= $row['is_simulated']?'SIMULATED':'Sensor reported' ?></span></td><td><?= detectionEscape($row['summary']) ?></td><td><?php if ($row['incident_id']): ?><a href="incidents.php?id=<?= detectionEscape($row['incident_id']) ?>">Case #<?= detectionEscape($row['incident_id']) ?></a><?php else: ?>No linked case<?php endif; ?></td></tr><?php endforeach; ?>
<?php if (!$result['rows']): ?><tr><td colspan="5" class="empty">No findings for this filter. Rules evaluate newly accepted sensor submissions; importing a threat feed alone does not create findings.</td></tr><?php endif; ?>
</tbody></table></div><div class="pages">Page <?= detectionEscape($result['page']) ?> of <?= detectionEscape($result['pages']) ?><div>
<?php if ($result['page']>1): ?><a href="detections.php?kind=<?= detectionEscape($kind) ?>&amp;page=<?= $result['page']-1 ?>">Previous</a><?php endif; ?>
<?php if ($result['page']<$result['pages']): ?><a href="detections.php?kind=<?= detectionEscape($kind) ?>&amp;page=<?= $result['page']+1 ?>">Next</a><?php endif; ?></div></div></section>
<?php endif; ?>
<?php if ($detail): ?><section class="panel" id="finding"><div class="panel-head"><h2>Finding #<?= detectionEscape($detail['id']) ?></h2><span class="badge <?= $detail['is_simulated']?'simulated':'' ?>"><?= $detail['is_simulated']?'SIMULATED TEST DATA':'Sensor reported' ?></span></div>
<p><?= detectionEscape($detail['summary']) ?></p>
<?php if ($detail['is_simulated']): ?><div class="notice">Simulation only. This finding cannot enter real incident correlation or trigger response actions.</div><?php endif; ?>
<h3>Supporting evidence</h3><ul><?php foreach ($detail['evidence'] as $e): ?><li><a href="events.php?log_id=<?= detectionEscape($e['log_id']) ?>#evidence">Inspect log #<?= detectionEscape($e['log_id']) ?></a> · <?= detectionEscape($e['source']) ?> · source event <?= detectionEscape($e['source_event_id'] ?? 'not supplied') ?> · received <?= detectionEscape($e['received_at']) ?> UTC</li><?php endforeach; ?></ul>
<details><summary>Rule settings at detection time (revision <?= detectionEscape($detail['rule_revision']) ?>)</summary><pre><?= detectionEscape(json_encode(json_decode($detail['rule_snapshot'], true), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre></details>
<details><summary>Detection context and intelligence attribution</summary><pre><?= detectionEscape(json_encode(json_decode($detail['context_json'], true), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre></details></section><?php endif; ?>
<?php if ($rules): ?><section class="panel"><h2>Rule settings</h2><p>Only administrators can change settings. Changes create an audited revision. A new finding is suppressed for the same source, submitter, IP, evidence type and rule revision until its window expires.</p>
<?php foreach ($rules as $rule): ?><article><h3><?= detectionEscape($rule['name']) ?></h3>
<p><?php if ($rule['rule_key']==='auth_failures'): ?>Counts explicit <code>metadata.event_type=authentication</code> and <code>metadata.outcome=failure</code>. Uses receipt time and preserves the latest threshold-sized evidence set.<?php else: ?>Matches an accepted event's source IP against stored intelligence. The window is a repeat-finding cooldown. Listings may be stale; inspect provider timestamps.<?php endif; ?></p>
<p>Revision <?= detectionEscape($rule['revision']) ?> · updated <?= detectionEscape($rule['updated_at']) ?> UTC by <?= detectionEscape($rule['updated_by']) ?></p>
<?php if ($canManage): ?><form method="post" class="filters">
<input type="hidden" name="csrf_token" value="<?= detectionEscape($_SESSION['csrf_token']) ?>"><input type="hidden" name="rule_key" value="<?= detectionEscape($rule['rule_key']) ?>"><input type="hidden" name="revision" value="<?= detectionEscape($rule['revision']) ?>">
<div class="field"><label for="enabled-<?= detectionEscape($rule['rule_key']) ?>">Status</label><select name="enabled" id="enabled-<?= detectionEscape($rule['rule_key']) ?>"><option value="1" <?= $rule['enabled']?'selected':'' ?>>Enabled</option><option value="0" <?= !$rule['enabled']?'selected':'' ?>>Disabled</option></select></div>
<div class="field"><label for="severity-<?= detectionEscape($rule['rule_key']) ?>">Severity</label><select name="severity" id="severity-<?= detectionEscape($rule['rule_key']) ?>"><?php foreach (['LOW','MEDIUM','HIGH','CRITICAL'] as $level): ?><option <?= $rule['severity']===$level?'selected':'' ?>><?= detectionEscape($level) ?></option><?php endforeach; ?></select></div>
<?php if ($rule['rule_key']==='auth_failures'): ?><div class="field"><label for="threshold">Failure threshold</label><input id="threshold" name="threshold_count" type="number" min="2" max="100" required value="<?= detectionEscape($rule['threshold_count']) ?>"></div><?php endif; ?>
<div class="field"><label for="window-<?= detectionEscape($rule['rule_key']) ?>">Window / cooldown (seconds)</label><input id="window-<?= detectionEscape($rule['rule_key']) ?>" name="window_seconds" type="number" min="60" max="86400" required value="<?= detectionEscape($rule['window_seconds']) ?>"></div><button type="submit">Save rule</button></form>
<?php else: ?><p><?= $rule['enabled']?'Enabled':'Disabled' ?> · <?= detectionEscape($rule['severity']) ?> · <?= detectionEscape($rule['threshold_count']) ?> event(s) · <?= detectionEscape($rule['window_seconds']) ?> seconds</p><?php endif; ?></article><?php endforeach; ?></section><?php endif; ?>
</main></div></body></html>
