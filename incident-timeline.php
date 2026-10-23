<?php
declare(strict_types=1);
require_once __DIR__.'/includes/db.php';
require_once __DIR__.'/includes/soar/SoarAuth.php';
require_once __DIR__.'/includes/soar/IncidentRepository.php';
require_once __DIR__.'/includes/soar/IncidentTimeline.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') { header('Location: login.php'); exit; }
if (!SoarAuth::hasPermission($auth['tier'], 'view_incidents')) {
    http_response_code(403); exit('Not authorized to view incidents.');
}
require_once __DIR__.'/includes/security.php';
header('Cache-Control: no-store');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header_remove('X-Powered-By');
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405); header('Allow: GET'); exit('Method not allowed.');
}
function timelineEscape(mixed $value): string {
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function timelineUrl(array $query): string { return 'incident-timeline.php?'.http_build_query($query); }
$id = filter_var($_GET['id'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: 0;
$page = filter_var($_GET['page'] ?? 1, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: 1;
$case = null; $history = null; $error = null;
try {
    if (!$id) throw new InvalidArgumentException('Select a valid incident.');
    $case = (new IncidentRepository($pdo))->find($id);
    if (!$case) throw new OutOfBoundsException('Incident not found.');
    $history = (new IncidentTimeline($pdo))->search($id, $_GET, $page);
} catch (InvalidArgumentException $e) {
    http_response_code(422); $error = $e->getMessage();
} catch (OutOfBoundsException $e) {
    http_response_code(404); $error = $e->getMessage();
} catch (Throwable $e) {
    http_response_code(503); error_log('Incident timeline failed: '.$e->getMessage());
    $error = 'Investigation history is temporarily unavailable. Please retry.';
}
?>
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse | Investigation timeline</title><link rel="stylesheet" href="assets/css/workspace.css"></head>
<body><a class="skip" href="#main">Skip to investigation timeline</a><div class="workspace">
<aside class="sidebar"><a class="brand" href="soc.php">ThreatPulse</a><nav aria-label="SOC navigation">
<a href="incidents.php">Incidents</a><a href="events.php">Event evidence</a><a href="notifications.php">My inbox</a>
</nav></aside><main id="main">
<span class="eyebrow">Investigation / recorded history</span><h1>Investigation timeline</h1>
<?php if ($id): ?><p><a href="incidents.php?id=<?= $id ?>#details">Back to case</a></p><?php endif; ?>
<?php if ($error): ?><div class="notice error" role="alert"><?= timelineEscape($error) ?></div><?php endif; ?>
<?php if ($case): ?>
<p><?= timelineEscape($case['incident_number']) ?> · <?= timelineEscape($case['title']) ?> · <?= timelineEscape($case['status']) ?></p>
<?php if (!empty($case['is_simulated'])): ?><div class="notice"><strong>SIMULATED CASE</strong> — this history belongs to a training scenario.</div><?php endif; ?>
<?php endif; ?>
<?php if ($history): $filters = $history['filters']; $query = ['id'=>$id] + $filters; ?>
<p>Search recorded summaries and actor names. Times are UTC. Structured event details and full note bodies are outside this search; read case notes and linked evidence on the case page.</p>
<section class="panel" aria-label="Timeline filters">
<form class="filters" method="get" action="incident-timeline.php">
<input type="hidden" name="id" value="<?= $id ?>">
<div class="field wide"><label for="q">Summary or actor name</label><input id="q" name="q" maxlength="200" value="<?= timelineEscape($filters['q']) ?>"></div>
<div class="field"><label for="event-type">Event type</label><select id="event-type" name="event_type">
<option value="">All event types</option>
<?php foreach (IncidentTimeline::EVENT_TYPES as $type): ?><option value="<?= timelineEscape($type) ?>" <?= $filters['event_type'] === $type ? 'selected' : '' ?>><?= timelineEscape(str_replace('_', ' ', $type)) ?></option><?php endforeach; ?>
</select></div>
<div class="field"><label for="actor-type">Actor type</label><select id="actor-type" name="actor_type">
<option value="">All actor types</option>
<?php foreach (IncidentTimeline::ACTOR_TYPES as $type): ?><option value="<?= timelineEscape($type) ?>" <?= $filters['actor_type'] === $type ? 'selected' : '' ?>><?= timelineEscape($type) ?></option><?php endforeach; ?>
</select></div>
<div class="field"><label for="sort">Order</label><select id="sort" name="sort">
<option value="newest" <?= $filters['sort'] === 'newest' ? 'selected' : '' ?>>Newest first</option>
<option value="oldest" <?= $filters['sort'] === 'oldest' ? 'selected' : '' ?>>Oldest first</option>
</select></div><button type="submit">Search history</button><a href="incident-timeline.php?id=<?= $id ?>">Clear filters</a>
</form></section>
<section class="panel" aria-label="Timeline results"><h2>Recorded events</h2>
<p><?= (int)$history['total'] ?> matching entries · up to 25 per page · <?= $filters['sort'] === 'oldest' ? 'oldest' : 'newest' ?> first. New entries may shift pages between visits.</p>
<div class="table-wrap"><table><thead><tr><th scope="col">Recorded (UTC) / ID</th><th scope="col">Event type</th><th scope="col">Actor</th><th scope="col">Summary</th></tr></thead><tbody>
<?php foreach ($history['rows'] as $event): ?>
<tr data-timeline-id="<?= (int)$event['id'] ?>"><td><?= timelineEscape($event['created_at']) ?><br>#<?= (int)$event['id'] ?></td><td><?= timelineEscape($event['event_type']) ?></td><td class="message"><?= timelineEscape($event['actor_name']) ?><br><span class="badge"><?= timelineEscape($event['actor_type']) ?></span></td><td class="message"><?= timelineEscape($event['summary']) ?></td></tr>
<?php endforeach; ?>
<?php if (!$history['rows']): ?><tr><td colspan="4">No timeline entries match these filters.</td></tr><?php endif; ?>
</tbody></table></div>
<nav class="pages" aria-label="Timeline pagination"><span>Page <?= (int)$history['page'] ?> of <?= (int)$history['pages'] ?></span><div>
<?php if ($history['page'] > 1): ?><a rel="prev" href="<?= timelineEscape(timelineUrl($query + ['page'=>$history['page'] - 1])) ?>">Previous</a><?php endif; ?>
<?php if ($history['page'] < $history['pages']): ?><a rel="next" href="<?= timelineEscape(timelineUrl($query + ['page'=>$history['page'] + 1])) ?>">Next</a><?php endif; ?>
</div></nav></section>
<?php endif; ?>
</main></div></body></html>
