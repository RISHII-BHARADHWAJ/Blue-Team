<?php
/** Authenticated evidence explorer. External intelligence and unclassified legacy logs stay separate. */
declare(strict_types=1);
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/soar/SoarAuth.php';
require_once __DIR__ . '/includes/siem/EventEvidenceRepository.php';
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') { header('Location: login.php'); exit; }
if (!SoarAuth::hasPermission($auth['tier'], 'view_alerts')) { http_response_code(403); exit('Not authorized to view events.'); }
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('Cache-Control: no-store');
header_remove('X-Powered-By');
function eventEscape(mixed $value): string { return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function eventUrl(array $params): string { return 'events.php?' . http_build_query($params); }
$filters = [];
foreach (['q', 'source_ip', 'severity', 'kind', 'from', 'to'] as $key) {
    $filters[$key] = is_string($_GET[$key] ?? null) ? substr(trim($_GET[$key]), 0, 200) : '';
}
// Preserve full exact source identities in drill-down links, including Unicode.
foreach (['source', 'submitted_by'] as $key) $filters[$key] = $_GET[$key] ?? '';
$page = filter_var($_GET['page'] ?? 1, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) ?: 1;
$logId = filter_var($_GET['log_id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) ?: null;
$repo = new EventEvidenceRepository($pdo);
$result = ['rows' => [], 'total' => 0, 'page' => 1, 'pages' => 1];
$available = false; $error = null; $detail = null;
try {
    $available = $repo->available();
    if ($available) {
        $result = $repo->search($filters, $page);
        if ($logId !== null) $detail = $repo->findByLogId($logId);
    }
} catch (InvalidArgumentException $e) {
    http_response_code(400); $error = $e->getMessage();
} catch (Throwable $e) {
    error_log('Event explorer failed: ' . $e->getMessage());
    http_response_code(503); $error = 'Event evidence is temporarily unavailable. Try again after checking database health.';
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse | Event evidence</title><link rel="stylesheet" href="assets/css/workspace.css"><?php require_once __DIR__.'/includes/ui/shell.php'; tpHead(''); ?>
</head><body class="tp-app tp-page-events"><?php tpShell('events',''); ?>
<a class="skip" href="#main">Skip to event evidence</a>
<div class="workspace"><aside class="sidebar"><a class="brand" href="soc.php">ThreatPulse</a>
<nav aria-label="SOC navigation"><a href="soc.php">Overview</a><a href="events.php" aria-current="page">Event evidence</a><a href="sources.php">Source activity</a><a href="detections.php">Detections</a><a href="threat-intel.php">Threat intelligence</a><a href="feeds.php">Feed health</a><a href="incidents.php">Incidents</a><a href="control_plane/index.php">SOAR approvals</a><a href="dashboard.php">Legacy SIEM</a></nav>
<p>Development environment<br>Evidence from authenticated submissions</p></aside><main id="main">
<span class="eyebrow">Investigate / source evidence</span><h1>Event evidence</h1>
<p>Search accepted sensor submissions and inspect their original evidence. A submitted alert is a source claim, not independent confirmation of an attack.</p>
<?php if ($error): ?><div class="notice error" role="alert"><?= eventEscape($error) ?></div><?php endif; ?>
<?php if (!$available && !$error): ?><div class="notice">Evidence storage is not initialized. Apply migration <code>008_event_evidence.sql</code> using the upgrade instructions before submitting new alerts.</div>
<?php elseif ($available): ?>
<div class="notice">Only submissions stored after the evidence upgrade appear here. External feed indicators remain in <a href="detections.php">Detections</a><a href="threat-intel.php">Threat intelligence</a>; older records remain in <a href="dashboard.php">Legacy SIEM</a> with unverified provenance.</div>
<section class="panel" aria-label="Event filters"><form class="filters" method="get" action="events.php">
<div class="field wide"><label for="q">Message or source event ID</label><input id="q" name="q" maxlength="200" value="<?= eventEscape($filters['q']) ?>" placeholder="Search submitted evidence"></div>
<div class="field"><label for="source">Source name (exact)</label><input id="source" name="source" maxlength="100" value="<?= eventEscape(is_string($filters['source']) ? $filters['source'] : '') ?>"></div>
<div class="field"><label for="submitted-by">Authenticated submitter (exact)</label><input id="submitted-by" name="submitted_by" maxlength="255" value="<?= eventEscape(is_string($filters['submitted_by']) ? $filters['submitted_by'] : '') ?>"></div>
<div class="field"><label for="source-ip">Source IP (exact)</label><input id="source-ip" name="source_ip" maxlength="45" value="<?= eventEscape($filters['source_ip']) ?>"></div>
<div class="field"><label for="severity">Source severity</label><select id="severity" name="severity"><option value="">All severities</option><?php foreach (['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as $value): ?><option <?= $filters['severity'] === $value ? 'selected' : '' ?>><?= eventEscape($value) ?></option><?php endforeach; ?></select></div>
<div class="field"><label for="kind">Evidence type</label><select id="kind" name="kind"><?php foreach ([''=>'All submissions','observed'=>'Sensor reported','simulated'=>'Simulated test data'] as $value=>$label): ?><option value="<?= eventEscape($value) ?>" <?= $filters['kind'] === $value ? 'selected' : '' ?>><?= eventEscape($label) ?></option><?php endforeach; ?></select></div>
<div class="field"><label for="from">Event date from (UTC)</label><input type="date" id="from" name="from" value="<?= eventEscape($filters['from']) ?>"></div>
<div class="field"><label for="to">Event date to (UTC)</label><input type="date" id="to" name="to" value="<?= eventEscape($filters['to']) ?>"></div>
<button type="submit">Search events</button><a href="events.php">Clear filters</a></form></section>
<?php if (!$error): ?>
<section class="panel" aria-labelledby="event-list"><div class="panel-head"><h2 id="event-list">Accepted events</h2><span class="muted"><?= eventEscape(number_format($result['total'])) ?> matching submissions</span></div>
<div class="table-wrap"><table><thead><tr><th>Event / received (UTC)</th><th>Source</th><th>Severity / type</th><th>Source IP</th><th>Evidence</th></tr></thead><tbody>
<?php foreach ($result['rows'] as $row): ?><tr>
<td><?= eventEscape($row['event_timestamp']) ?><br><span class="muted">Received <?= eventEscape($row['received_at']) ?></span><?php if ($row['timestamp_origin'] === 'receipt_fallback'): ?><br><span class="badge">Time inferred from receipt</span><?php endif; ?></td>
<td><?= eventEscape($row['source']) ?><br><span class="muted"><?= eventEscape($row['source_type']) ?></span><br>Submitted by <?= eventEscape($row['submitted_by']) ?></td>
<td><span class="badge <?= eventEscape($row['severity']) ?>"><?= eventEscape($row['severity'] === 'WARNING' ? 'MEDIUM' : $row['severity']) ?></span><br><span class="badge <?= $row['is_simulated'] ? 'simulated' : '' ?>"><?= $row['is_simulated'] ? 'SIMULATED' : 'Sensor reported' ?></span></td>
<td><code><?= eventEscape($row['source_ip'] ?? 'Not supplied') ?></code></td>
<td class="message"><a href="<?= eventEscape(eventUrl(array_merge($filters, ['page'=>$result['page'], 'log_id'=>$row['log_id']]))) ?>#evidence">Inspect log #<?= eventEscape($row['log_id']) ?></a><br><?= eventEscape(substr($row['message'], 0, 200)) ?></td></tr><?php endforeach; ?>
<?php if (!$result['rows']): ?><tr><td colspan="5" class="empty">No matching events. Connect an authorized sensor or adjust your filters. Intelligence feed imports do not populate this view.</td></tr><?php endif; ?>
</tbody></table></div><div class="pages"><span>Page <?= eventEscape($result['page']) ?> of <?= eventEscape($result['pages']) ?></span><div>
<?php if ($result['page'] > 1): ?><a href="<?= eventEscape(eventUrl(array_merge($filters, ['page'=>$result['page']-1]))) ?>">Previous</a><?php endif; ?>
<?php if ($result['page'] < $result['pages']): ?><a href="<?= eventEscape(eventUrl(array_merge($filters, ['page'=>$result['page']+1]))) ?>">Next</a><?php endif; ?></div></div></section>
<?php if ($logId && !$detail): ?><section class="panel">No stored submission evidence for log #<?= eventEscape($logId) ?>. This may be a legacy record, which cannot be retrospectively attributed.</section><?php endif; ?>
<?php if ($detail): $canonical = json_decode($detail['canonical_json'], true, 512, JSON_THROW_ON_ERROR); ?>
<section class="panel" id="evidence" aria-labelledby="evidence-title"><div class="panel-head"><h2 id="evidence-title">Evidence · log #<?= eventEscape($detail['log_id']) ?></h2><span class="badge <?= $detail['is_simulated'] ? 'simulated' : '' ?>"><?= $detail['is_simulated'] ? 'SIMULATED TEST DATA' : 'Sensor reported' ?></span></div>
<?php if ($detail['is_simulated']): ?><div class="notice">Simulation only. This submission is excluded from real incident correlation and cannot be manually attached to a real case.</div><?php endif; ?>
<dl class="facts">
<?php foreach (['Claimed source'=>$detail['source'], 'Authenticated submitter'=>$detail['submitted_by'], 'Source event ID'=>$detail['source_event_id'] ?? 'Not supplied', 'Event time (UTC)'=>$detail['event_timestamp'], 'Receipt time (UTC)'=>$detail['received_at'], 'Timestamp origin'=>$detail['timestamp_origin'], 'Destination IP'=>$canonical['destination_ip'] ?? 'Not supplied', 'Protocol'=>$canonical['protocol'] ?? 'Not supplied', 'Source signature'=>$canonical['signature'] ?? 'Not supplied'] as $label=>$value): ?><div><dt><?= eventEscape($label) ?></dt><dd><?= eventEscape($value) ?></dd></div><?php endforeach; ?></dl>
<h3>Linked incidents</h3><?php foreach ($detail['incidents'] as $incident): ?><p><a href="incidents.php?id=<?= eventEscape($incident['id']) ?>"><?= eventEscape($incident['incident_number']) ?></a> · <?= eventEscape($incident['status']) ?> · <?= eventEscape($incident['correlation_rule']) ?></p><?php endforeach; ?>
<?php if (!$detail['incidents']): ?><p>No linked incident. Storing an event does not mean it meets the incident correlation threshold.</p><?php endif; ?>
<?php if (!$detail['incidents'] && !$detail['is_simulated'] && $auth['auth_method']==='session' && !empty($auth['user_id']) && SoarAuth::hasPermission($auth['tier'],'manual_escalate')): ?><p><a href="event-escalate.php?log_id=<?= (int)$detail['log_id'] ?>">Review and open an investigation case →</a></p><?php endif; ?>
<h3>Original message</h3><pre><?= eventEscape($canonical['message']) ?></pre>
<details><summary>Normalized fields and metadata</summary><pre><?= eventEscape(json_encode($canonical, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></pre></details>
<details><summary>Original submitted payload</summary><p><?= $detail['payload_encoding'] === 'http_body' ? 'Exact HTTP request body; authentication headers are not stored.' : 'JSON re-encoded from a service call; original HTTP bytes were not supplied.' ?></p><pre><?= eventEscape($detail['raw_payload']) ?></pre></details>
<p>Stored payload SHA-256: <code><?= eventEscape($detail['payload_sha256']) ?></code><br>Checksum of the stored bytes, not an independent signature or guarantee against database tampering.</p>
</section><?php endif; ?>
<?php endif; endif; ?>
</main></div></body></html>
