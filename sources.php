<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/siem/SourceActivityService.php';
$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') { header('Location: login.php'); exit; }
if (!SoarAuth::hasPermission($auth['tier'], 'view_alerts')) { http_response_code(403); exit('Not authorized to view source activity.'); }
header('Cache-Control: no-store');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header_remove('X-Powered-By');
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { http_response_code(405); header('Allow: GET'); exit('Method not allowed.'); }
function sourceEscape(mixed $value): string { return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function sourceUrl(array $query): string { return 'sources.php?'.http_build_query($query); }
$filters = SourceActivityService::filters([]);
$view = null; $error = null;
$page = filter_var($_GET['page'] ?? 1, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: 1;
try {
    $filters = SourceActivityService::filters($_GET);
    $view = (new SourceActivityService($pdo))->search($filters, $page);
} catch (InvalidArgumentException $e) {
    http_response_code(422); $error = $e->getMessage();
} catch (Throwable $e) {
    http_response_code(503); error_log('Source activity unavailable: '.$e->getMessage());
    $error = 'Source activity is unavailable. Check evidence migration 008 and database health, then retry.';
}
$activityLabels = ['recent'=>'Received in window', 'quiet'=>'No receipts in window', 'clock'=>'Future receipt recorded'];
?>
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse | Source activity</title><link rel="stylesheet" href="assets/css/workspace.css"></head>
<body><a class="skip" href="#main">Skip to source activity</a><div class="workspace">
<aside class="sidebar"><a class="brand" href="soc.php">ThreatPulse</a><nav aria-label="SOC navigation">
<a href="soc.php">Overview</a><a href="events.php">Event evidence</a><a href="sources.php" aria-current="page">Source activity</a><a href="feeds.php">Feed health</a><a href="incidents.php">Incidents</a>
</nav></aside><main id="main"><span class="eyebrow">SIEM / receipt activity</span><h1>Telemetry source activity</h1>
<p>See when previously observed sources submitted evidence. Each row pairs an authenticated submitter with a claimed source name; shared credentials may represent several sensors.</p>
<div class="notice">Activity measures stored, accepted submissions. It does not prove sensor health or network reachability. Sources that never submitted are unknown here; rejected requests, suppressed duplicates, external feed imports and legacy logs without preserved provenance are not counted.</div>
<?php if ($error): ?><div class="notice error" role="alert"><?= sourceEscape($error) ?></div><?php endif; ?>
<?php if ($filters['kind'] === 'simulated'): ?><div class="notice"><strong>SIMULATED TEST DATA</strong> — these receipts describe training submissions.</div><?php endif; ?>
<section class="panel" aria-label="Source filters"><form class="filters" method="get" action="sources.php">
<div class="field wide"><label for="q">Claimed source or authenticated submitter</label><input id="q" name="q" maxlength="200" value="<?= sourceEscape($filters['q']) ?>"></div>
<div class="field"><label for="kind">Evidence type</label><select id="kind" name="kind">
<?php foreach (['observed'=>'Sensor reported', 'simulated'=>'Simulated only'] as $value=>$label): ?><option value="<?= sourceEscape($value) ?>" <?= $filters['kind'] === $value ? 'selected' : '' ?>><?= sourceEscape($label) ?></option><?php endforeach; ?>
</select></div>
<div class="field"><label for="hours">Receipt window</label><select id="hours" name="hours">
<?php foreach (['1'=>'Last hour', '24'=>'Last 24 hours', '168'=>'Last 7 days'] as $value=>$label): ?><option value="<?= sourceEscape($value) ?>" <?= $filters['hours'] === (string)$value ? 'selected' : '' ?>><?= sourceEscape($label) ?></option><?php endforeach; ?>
</select></div>
<div class="field"><label for="activity">Activity</label><select id="activity" name="activity">
<?php foreach (['all'=>'All activity'] + $activityLabels as $value=>$label): ?><option value="<?= sourceEscape($value) ?>" <?= $filters['activity'] === $value ? 'selected' : '' ?>><?= sourceEscape($label) ?></option><?php endforeach; ?>
</select></div>
<div class="field"><label for="sort">Order</label><select id="sort" name="sort">
<?php foreach (['newest'=>'Latest receipt first', 'oldest'=>'Oldest last receipt first', 'volume'=>'Most receipts in window'] as $value=>$label): ?><option value="<?= sourceEscape($value) ?>" <?= $filters['sort'] === $value ? 'selected' : '' ?>><?= sourceEscape($label) ?></option><?php endforeach; ?>
</select></div><button type="submit">View activity</button><a href="sources.php">Clear filters</a>
</form></section>
<?php if ($view): ?>
<section class="panel" aria-label="Source results"><h2>Observed source identities</h2>
<p><?= (int)$view['total'] ?> matching submitter/source pairs · up to 25 per page. Receipt window: <?= sourceEscape($view['since_utc']) ?> through <?= sourceEscape($view['as_of_utc']) ?> UTC.</p>
<p>First and last receipt exclude future timestamps. A future receipt is flagged separately and does not count as recent activity. Event timestamps supplied by sensors do not determine this view.</p>
<div class="table-wrap"><table><thead><tr><th scope="col">Authenticated submitter / claimed source</th><th scope="col">Activity</th><th scope="col">Receipts in window / all stored</th><th scope="col">First / last receipt (UTC)</th><th scope="col">Evidence</th></tr></thead><tbody>
<?php foreach ($view['rows'] as $row): ?>
<tr data-source-row="1"><td class="message"><strong><?= sourceEscape($row['submitted_by']) ?></strong><br><?= sourceEscape($row['source']) ?></td>
<td><span class="badge <?= $row['activity'] === 'clock' ? 'WARNING' : '' ?>"><?= sourceEscape($activityLabels[$row['activity']]) ?></span><?php if ($row['future_count']): ?><br><?= (int)$row['future_count'] ?> future receipt(s)<?php endif; ?></td>
<td><?= (int)$row['recent_count'] ?> / <?= (int)$row['stored_count'] ?></td><td><?= sourceEscape($row['first_received_at'] ?? 'No non-future receipt') ?><br><?= sourceEscape($row['last_received_at'] ?? 'No non-future receipt') ?></td>
<td><a href="<?= sourceEscape('events.php?'.http_build_query(['kind'=>$filters['kind'], 'source'=>$row['source'], 'submitted_by'=>$row['submitted_by']])) ?>">Inspect all preserved events</a></td></tr>
<?php endforeach; ?>
<?php if (!$view['rows']): ?><tr><td colspan="5">No sources match these filters. Only identities with preserved submissions can appear.</td></tr><?php endif; ?>
</tbody></table></div>
<nav class="pages" aria-label="Source pagination"><span>Page <?= (int)$view['page'] ?> of <?= (int)$view['pages'] ?></span><div>
<?php if ($view['page'] > 1): ?><a rel="prev" href="<?= sourceEscape(sourceUrl($filters + ['page'=>$view['page'] - 1])) ?>">Previous</a><?php endif; ?>
<?php if ($view['page'] < $view['pages']): ?><a rel="next" href="<?= sourceEscape(sourceUrl($filters + ['page'=>$view['page'] + 1])) ?>">Next</a><?php endif; ?>
</div></nav></section>
<?php endif; ?>
</main></div></body></html>
