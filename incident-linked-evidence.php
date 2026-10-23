<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/soar/IncidentLinkedEvidenceWorkspace.php';
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') { header('Location: login.php'); exit; }
if (!SoarAuth::hasPermission($auth['tier'],'view_incidents')) { http_response_code(403); exit('Not authorized to view incidents.'); }
header('Cache-Control: no-store'); header('X-Frame-Options: DENY'); header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin'); header_remove('X-Powered-By');
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { http_response_code(405); header('Allow: GET'); exit('Method not allowed.'); }
function linkedEscape(mixed $value): string { return htmlspecialchars((string)($value ?? ''),ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8'); }
function linkedUrl(array $query): string { return 'incident-linked-evidence.php?'.http_build_query($query); }
$id = filter_var($_GET['id'] ?? null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]) ?: 0;
$page = filter_var($_GET['page'] ?? 1,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]) ?: 1;
$view = null; $error = null;
try { $view = (new IncidentLinkedEvidenceWorkspace($pdo))->view($id,$_GET,$page); }
catch (InvalidArgumentException $e) { http_response_code(422); $error = $e->getMessage(); }
catch (OutOfBoundsException $e) { http_response_code(404); $error = $e->getMessage(); }
catch (Throwable $e) {
    http_response_code(503); error_log('Linked evidence unavailable: '.$e->getMessage());
    $error = 'Linked evidence is unavailable. Check evidence migration 008 and database health, then retry.';
}
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse | Linked case evidence</title><link rel="stylesheet" href="assets/css/workspace.css"></head>
<body><a class="skip" href="#main">Skip to linked evidence</a><div class="workspace"><aside class="sidebar"><a class="brand" href="soc.php">ThreatPulse</a>
<nav aria-label="SOC navigation"><a href="incidents.php">Incidents</a><a href="events.php">Event evidence</a><a href="sources.php">Source activity</a></nav></aside>
<main id="main"><span class="eyebrow">Investigation / case evidence</span><h1>Linked case evidence</h1>
<?php if ($id): ?><p><a href="incidents.php?id=<?= $id ?>#details">Back to case</a> · <a href="incident-timeline.php?id=<?= $id ?>">Investigation timeline</a></p><?php endif; ?>
<?php if ($error): ?><div class="notice error" role="alert"><?= linkedEscape($error) ?></div><?php endif; ?>
<?php if ($view): $case = $view['incident']; $filters = $view['filters']; $query = ['id'=>$id] + $filters; ?>
<p><?= linkedEscape($case['incident_number']) ?> · <?= linkedEscape($case['title']) ?> · <?= linkedEscape($case['status']) ?></p>
<?php if (!empty($case['is_simulated'])): ?><div class="notice"><strong>SIMULATED CASE</strong> — these associations belong to a training scenario.</div>
<?php else: ?><p><a href="incident-evidence.php?id=<?= $id ?>">Find and link additional preserved evidence</a></p><?php endif; ?>
<p>Search events already linked to this case. A recorded association or correlation rule is investigation context, not proof of an attack. Legacy logs have no preserved submission provenance.</p>
<section class="panel" aria-label="Evidence filters"><form class="filters" method="get" action="incident-linked-evidence.php">
<input type="hidden" name="id" value="<?= $id ?>">
<div class="field wide"><label for="q">Message or source event ID</label><input id="q" name="q" maxlength="200" value="<?= linkedEscape($filters['q']) ?>"></div>
<div class="field"><label for="source-ip">Source IP (exact)</label><input id="source-ip" name="source_ip" maxlength="45" value="<?= linkedEscape($filters['source_ip']) ?>"></div>
<div class="field"><label for="severity">Source severity</label><select id="severity" name="severity"><option value="">All severities</option>
<?php foreach (['CRITICAL','HIGH','MEDIUM','LOW','INFO'] as $value): ?><option value="<?= $value ?>" <?= $filters['severity'] === $value ? 'selected' : '' ?>><?= $value ?></option><?php endforeach; ?></select></div>
<div class="field"><label for="provenance">Provenance</label><select id="provenance" name="provenance">
<?php foreach (['all'=>'All linked logs','preserved'=>'Preserved submission','legacy'=>'Legacy log only'] as $value=>$label): ?><option value="<?= $value ?>" <?= $filters['provenance'] === $value ? 'selected' : '' ?>><?= $label ?></option><?php endforeach; ?></select></div>
<div class="field"><label for="sort">Order</label><select id="sort" name="sort">
<?php foreach (['event_newest'=>'Newest event first','event_oldest'=>'Oldest event first','attached_newest'=>'Most recently linked'] as $value=>$label): ?><option value="<?= $value ?>" <?= $filters['sort'] === $value ? 'selected' : '' ?>><?= $label ?></option><?php endforeach; ?></select></div>
<button type="submit">Search linked evidence</button><a href="incident-linked-evidence.php?id=<?= $id ?>">Clear filters</a>
</form></section>
<section class="panel" aria-label="Linked evidence results"><h2>Existing evidence associations</h2><p><?= (int)$view['total'] ?> matching links · up to 25 per page. Messages show at most 500 characters; search covers the full stored log message.</p>
<p>Preserved event and receipt times are UTC. Legacy log times and link times use database server time.</p>
<div class="table-wrap"><table><thead><tr><th scope="col">Event / link time</th><th scope="col">Source / provenance</th><th scope="col">Severity / source IP</th><th scope="col">Message / association</th></tr></thead><tbody>
<?php foreach ($view['rows'] as $row): ?>
<tr data-linked-log="<?= (int)$row['log_id'] ?>"><td><?= linkedEscape($row['event_timestamp']) ?><br>Linked <?= linkedEscape($row['attached_at']) ?><?php if ($row['received_at']): ?><br>Received <?= linkedEscape($row['received_at']) ?><?php endif; ?></td>
<td class="message"><?php if ($row['evidence_id'] !== null): ?><strong><?= linkedEscape($row['source']) ?></strong><br>Submitted by <?= linkedEscape($row['submitted_by']) ?><br><span class="badge <?= $row['is_simulated'] ? 'simulated' : '' ?>"><?= $row['is_simulated'] ? 'SIMULATED EVIDENCE' : 'Preserved submission' ?></span><br><a href="events.php?log_id=<?= (int)$row['log_id'] ?>#evidence">Inspect evidence #<?= (int)$row['log_id'] ?></a>
<?php else: ?><span class="badge">Legacy log — provenance unavailable</span><br>Log #<?= (int)$row['log_id'] ?><?php endif; ?></td>
<td><?= linkedEscape($row['severity'] === 'WARNING' ? 'MEDIUM' : $row['severity']) ?><br><?= linkedEscape($row['source_ip'] ?? 'Not supplied') ?></td>
<td class="message"><?= linkedEscape($row['message']) ?><?= $row['message_truncated'] ? '… [preview truncated]' : '' ?><br><span class="muted">Linked via <?= linkedEscape($row['correlation_rule']) ?></span></td></tr>
<?php endforeach; ?>
<?php if (!$view['rows']): ?><tr><td colspan="4">No linked evidence matches these filters.</td></tr><?php endif; ?>
</tbody></table></div><nav class="pages" aria-label="Linked evidence pagination"><span>Page <?= (int)$view['page'] ?> of <?= (int)$view['pages'] ?></span><div>
<?php if ($view['page'] > 1): ?><a rel="prev" href="<?= linkedEscape(linkedUrl($query + ['page'=>$view['page']-1])) ?>">Previous</a><?php endif; ?>
<?php if ($view['page'] < $view['pages']): ?><a rel="next" href="<?= linkedEscape(linkedUrl($query + ['page'=>$view['page']+1])) ?>">Next</a><?php endif; ?>
</div></nav></section><?php endif; ?>
</main></div></body></html>
