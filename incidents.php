<?php
/**
 * ThreatPulse SOC incident queue and controlled analyst triage surface.
 * Changes are submitted only through the authorized incident API.
 */
declare(strict_types=1);

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/soar/SoarAuth.php';
require_once __DIR__ . '/includes/soar/IncidentManager.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    header('Location: login.php');
    exit;
}
if (!SoarAuth::hasPermission($auth['tier'], 'view_incidents')) {
    http_response_code(403);
    exit('Not authorized to view incidents.');
}

require_once __DIR__ . '/includes/security.php';
$canTriage = SoarAuth::hasPermission($auth['tier'], 'change_status_normal');
$canClose = SoarAuth::hasPermission($auth['tier'], 'close_incidents');
$csrfToken = $canTriage ? generateCSRFToken() : '';

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header_remove('X-Powered-By');

function incidentEscape(mixed $value): string {
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$status = is_string($_GET['status'] ?? null) ? strtoupper(trim($_GET['status'])) : '';
$severity = is_string($_GET['severity'] ?? null) ? strtoupper(trim($_GET['severity'])) : '';
$validStatuses = ['NEW', 'OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'];
$validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
if (!in_array($status, $validStatuses, true)) $status = '';
if (!in_array($severity, $validSeverities, true)) $severity = '';
$page = isset($_GET['page']) && is_scalar($_GET['page'])
    ? min(1000, max(1, (int)$_GET['page'])) : 1;
$selectedId = isset($_GET['id']) && is_scalar($_GET['id'])
    ? filter_var($_GET['id'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) : false;

$manager = new IncidentManager($pdo);
$repository = new IncidentRepository($pdo);
$filters = array_filter(['status' => $status, 'severity' => $severity]);
$error = null;
$rows = [];
$total = 0;
$detail = null;
try {
    $total = $repository->countIncidents($filters);
    $rows = $manager->listIncidents($filters, 25, ($page - 1) * 25);
    if ($selectedId !== false) {
        $detail = $manager->getIncident((int)$selectedId);
    }
} catch (Throwable $e) {
    error_log('Incident queue failed: ' . $e->getMessage());
    $error = 'Incident records are temporarily unavailable.';
}

$triageTransitions = [];
if ($detail !== null && $canTriage) {
    // Never imply host containment from a manual status update.
    // Containment requires a separate validated response workflow.
    $triageTransitions = match ($detail['status']) {
        'NEW' => ['OPEN'],
        'OPEN' => ['INVESTIGATING'],
        'INVESTIGATING', 'CONTAINED' => ['RESOLVED'],
        'RESOLVED' => $canClose ? ['CLOSED'] : [],
        default => [],
    };
}

function incidentUrl(array $params): string {
    return 'incidents.php?' . http_build_query(array_filter($params, static fn($v) => $v !== '' && $v !== null));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse SOC | Incident Queue</title>
<style>
:root{color-scheme:dark;--bg:#020b18;--panel:#071629;--line:#183652;--text:#e0eeff;--muted:#92b0ce;--cyan:#17d4be;--amber:#ffb703}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 system-ui,Arial,sans-serif}
a{color:#5ed8ee}header{display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding:16px max(20px,calc((100vw - 1180px)/2))}
.brand{color:var(--cyan);font-weight:800;letter-spacing:1.2px;font-size:19px;text-decoration:none}nav{display:flex;gap:18px}main{max-width:1180px;margin:auto;padding:25px 20px 60px}
h1{margin:0;font-size:29px}h2{font-size:20px;margin:0 0 15px}.lead{color:var(--muted);margin:3px 0 25px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px;margin:16px 0}
form{display:flex;align-items:end;flex-wrap:wrap;gap:15px}.field{display:flex;flex-direction:column;gap:4px}.field label{color:var(--muted);font-size:12px}
select,button{border:1px solid #376285;color:var(--text);background:#0d2541;padding:9px 12px;border-radius:6px;font:inherit}
button{cursor:pointer}button:hover{background:#16436d}table{width:100%;border-collapse:collapse}th{text-align:left;color:var(--muted);font-size:11px;letter-spacing:1px}
th,td{padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}tr:hover td{background:#0b2440}
.table-scroll{overflow:auto}.muted{color:var(--muted)}.pill{font-size:11px;font-weight:800;border:1px solid #497293;border-radius:30px;padding:3px 9px;white-space:nowrap}
.CRITICAL{color:#ff7979;border-color:#c44242}.HIGH{color:#ffb367;border-color:#9a6728}.MEDIUM{color:#f9d47c}.LOW,.INFO{color:#7fcfaa}
.metrics{display:flex;gap:12px;align-items:center}.metric{font-size:24px;font-weight:800;color:var(--cyan)}
.pager{display:flex;justify-content:space-between;gap:15px;align-items:center;margin-top:18px}.pager a{border:1px solid var(--line);padding:7px 13px;border-radius:5px;text-decoration:none}
.info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px;margin-bottom:20px}.info-grid div{background:#0b223c;border-radius:8px;padding:12px;overflow-wrap:anywhere}.info-grid strong{display:block;font-size:12px;color:var(--muted)}
.event{padding:12px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.event strong{color:#84deeb}.event small{color:var(--muted);display:block}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;margin:6px 0}.error{border-color:#ba3f4b;color:#ff9d9d}.triage{background:#09243b;border:1px solid #265b76;border-radius:9px;padding:15px;margin:20px 0}.triage p{margin:0 0 12px;color:var(--muted)}.triage input{border:1px solid #376285;color:var(--text);background:#0d2541;padding:9px 12px;border-radius:6px;min-width:250px;flex:1;font:inherit}.triage button:disabled{opacity:.6;cursor:wait}.triage-feedback{margin-top:10px;color:#ffb8b8}
@media(max-width:700px){th,td{padding:8px 5px;font-size:12px}main{padding:20px 12px}.panel{padding:13px}}
</style>
</head>
<body>
<header><a class="brand" href="dashboard.php">THREATPULSE / SOC</a><nav><a href="dashboard.php">SIEM Dashboard</a><a href="incidents.php" aria-current="page">Incidents</a><a href="control_plane/index.php">SOAR Control Plane</a></nav></header>
<main>
<h1>Incident queue</h1>
<p class="lead">Review correlated detections, attached SIEM alerts, and the investigation timeline. Status progression uses the permission-checked incident API. Host containment actions are never initiated here.</p>
<?php if ($error !== null): ?><section class="panel error" role="alert"><?= incidentEscape($error) ?></section><?php endif; ?>
<section class="panel">
<form method="get" action="incidents.php">
<div class="field"><label for="status">Status</label><select id="status" name="status"><option value="">All statuses</option>
<?php foreach ($validStatuses as $choice): ?><option value="<?= incidentEscape($choice) ?>" <?= $status === $choice ? 'selected' : '' ?>><?= incidentEscape($choice) ?></option><?php endforeach; ?></select></div>
<div class="field"><label for="severity">Severity</label><select id="severity" name="severity"><option value="">All severities</option>
<?php foreach ($validSeverities as $choice): ?><option value="<?= incidentEscape($choice) ?>" <?= $severity === $choice ? 'selected' : '' ?>><?= incidentEscape($choice) ?></option><?php endforeach; ?></select></div>
<button type="submit">Apply filters</button><a href="incidents.php">Clear</a>
</form>
</section>
<section class="panel">
<div class="metrics"><span class="metric"><?= incidentEscape($total) ?></span><span class="muted">matching incidents · showing up to 25 per page</span></div>
<div class="table-scroll"><table><thead><tr><th>Incident</th><th>Title</th><th>Severity</th><th>Status</th><th>Priority</th><th>Alerts</th><th>Created</th></tr></thead><tbody>
<?php foreach ($rows as $incident): ?>
<tr>
<td><a href="<?= incidentEscape(incidentUrl(['id' => $incident['id'], 'status' => $status, 'severity' => $severity, 'page' => $page])) ?>"><?= incidentEscape($incident['incident_number']) ?></a></td>
<td><?= incidentEscape($incident['title']) ?></td>
<td><span class="pill <?= incidentEscape($incident['severity']) ?>"><?= incidentEscape($incident['severity']) ?></span></td>
<td><?= incidentEscape($incident['status']) ?></td>
<td><?= incidentEscape($incident['priority']) ?></td>
<td><?= incidentEscape($incident['alert_count']) ?></td>
<td class="muted"><?= incidentEscape($incident['created_at']) ?></td>
</tr>
<?php endforeach; ?>
<?php if (!$rows): ?><tr><td colspan="7" class="muted">No incidents match these filters.</td></tr><?php endif; ?>
</tbody></table></div>
<div class="pager"><span class="muted">Page <?= incidentEscape($page) ?> of <?= incidentEscape(max(1,(int)ceil($total/25))) ?></span>
<div>
<?php if ($page > 1): ?><a href="<?= incidentEscape(incidentUrl(['status'=>$status,'severity'=>$severity,'page'=>$page-1])) ?>">Previous</a><?php endif; ?>
<?php if ($page * 25 < $total): ?><a href="<?= incidentEscape(incidentUrl(['status'=>$status,'severity'=>$severity,'page'=>$page+1])) ?>">Next</a><?php endif; ?>
</div></div>
</section>
<?php if ($selectedId !== false): ?>
<section class="panel" id="details">
<h2><?= $detail ? incidentEscape($detail['incident_number']) . ' · ' . incidentEscape($detail['title']) : 'Incident not found' ?></h2>
<?php if ($detail): ?>
<div class="info-grid">
<div><strong>Status</strong><?= incidentEscape($detail['status']) ?></div>
<div><strong>Severity / Priority</strong><?= incidentEscape($detail['severity']) ?> / <?= incidentEscape($detail['priority']) ?></div>
<div><strong>Attack category</strong><?= incidentEscape($detail['attack_category'] ?: 'Unclassified') ?></div>
<div><strong>Assigned analyst</strong><?= incidentEscape($detail['assigned_username'] ?: 'Unassigned') ?></div>
</div>
<?php if ($triageTransitions): ?>
<div class="triage">
<h2>Analyst triage</h2>
<p>Choose a permitted next state and record a reason. This updates the incident timeline; it does not execute any containment or host action.</p>
<form id="triage-form" data-incident-id="<?= incidentEscape($detail['id']) ?>">
<input type="hidden" name="csrf_token" value="<?= incidentEscape($csrfToken) ?>">
<div class="field"><label for="new-status">Next status</label><select id="new-status" name="new_status" required>
<?php foreach ($triageTransitions as $nextStatus): ?><option value="<?= incidentEscape($nextStatus) ?>"><?= incidentEscape($nextStatus) ?></option><?php endforeach; ?>
</select></div>
<div class="field" style="flex:1"><label for="triage-reason">Reason for change</label><input id="triage-reason" name="reason" required maxlength="500" placeholder="Briefly explain the investigation decision"></div>
<button type="submit">Update incident</button>
</form>
<div id="triage-feedback" class="triage-feedback" role="status" aria-live="polite"></div>
</div>
<?php elseif (!$canTriage): ?>
<p class="muted">Read-only access: Tier 2 or higher is required to progress an incident.</p>
<?php endif; ?>
<h2>Description</h2><pre><?= incidentEscape($detail['description']) ?></pre>
<h2>Linked SIEM alerts (<?= count($detail['alerts']) ?>)</h2>
<?php foreach ($detail['alerts'] as $alert): ?><div class="event"><strong><?= incidentEscape($alert['category']) ?> · <?= incidentEscape($alert['severity']) ?></strong><small><?= incidentEscape($alert['event_timestamp']) ?> · Source <?= incidentEscape($alert['source_ip']) ?> · Log #<?= incidentEscape($alert['log_id']) ?></small><pre><?= incidentEscape($alert['message']) ?></pre></div><?php endforeach; ?>
<?php if (!$detail['alerts']): ?><p class="muted">No linked SIEM logs.</p><?php endif; ?>
<h2 style="margin-top:20px">Investigation timeline</h2>
<?php foreach ($detail['timeline'] as $event): ?><div class="event"><strong><?= incidentEscape($event['event_type']) ?></strong><small><?= incidentEscape($event['created_at']) ?> · <?= incidentEscape($event['actor_name']) ?></small><?= incidentEscape($event['summary']) ?></div><?php endforeach; ?>
<?php if (!$detail['timeline']): ?><p class="muted">No timeline entries yet.</p><?php endif; ?>
<?php endif; ?>
</section>
<?php endif; ?>
</main>
<script>
(function () {
    const form = document.getElementById('triage-form');
    if (!form) return;
    const feedback = document.getElementById('triage-feedback');
    form.addEventListener('submit', async function (event) {
        event.preventDefault();
        const data = new FormData(form);
        const nextStatus = String(data.get('new_status') || '');
        const reason = String(data.get('reason') || '').trim();
        if (!reason) { feedback.textContent = 'Please provide a reason.'; return; }
        if (nextStatus === 'CLOSED' && !window.confirm('Close this incident? Closed incidents cannot be reopened.')) return;
        const button = form.querySelector('button[type="submit"]');
        button.disabled = true;
        feedback.textContent = 'Saving incident status...';
        try {
            const response = await fetch('api/v1/incidents_detail.php', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': String(data.get('csrf_token') || '')
                },
                body: JSON.stringify({
                    id: Number(form.dataset.incidentId),
                    action: 'change_status',
                    new_status: nextStatus,
                    reason: reason
                })
            });
            const result = await response.json();
            if (!response.ok || result.success !== true) {
                feedback.textContent = result.message || 'Status update failed. Please retry.';
                return;
            }
            window.location.reload();
        } catch (_) {
            feedback.textContent = 'Could not contact the incident API. Please retry.';
        } finally {
            button.disabled = false;
        }
    });
})();
</script>
</body>
</html>
