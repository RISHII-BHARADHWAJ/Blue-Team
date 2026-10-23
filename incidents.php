<?php
/**
 * ThreatPulse SOC incident queue and controlled analyst triage surface.
 * Changes are submitted only through the authorized incident API.
 */
declare(strict_types=1);

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/soar/SoarAuth.php';
require_once __DIR__ . '/includes/soar/IncidentManager.php';
require_once __DIR__ . '/includes/soar/IncidentQueueQuery.php';
require_once __DIR__ . '/includes/soar/CaseNoteService.php';
require_once __DIR__ . '/includes/soar/ThreatIntelMatcher.php';

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
$canAssign = SoarAuth::hasPermission($auth['tier'], 'assign_incidents');
$canClose = SoarAuth::hasPermission($auth['tier'], 'close_incidents');
$canNote = $auth['auth_method'] === 'session' && !empty($auth['user_id']) && SoarAuth::hasPermission($auth['tier'], 'add_notes');
$csrfToken = ($canTriage || $canNote) ? generateCSRFToken() : '';

header('Cache-Control: no-store');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header_remove('X-Powered-By');

function incidentEscape(mixed $value): string {
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$myUserId = isset($auth['user_id']) && (int)$auth['user_id'] > 0 ? (int)$auth['user_id'] : null;
try {
    $queueInput = IncidentQueueQuery::parse($_GET, $myUserId);
} catch (InvalidArgumentException $e) {
    http_response_code(422);
    exit(incidentEscape($e->getMessage()));
}
$query = $queueInput['query'];
$filters = $queueInput['filters'];
$page = $queueInput['page'];
$kind = $query['kind']; $status = $query['status']; $severity = $query['severity'];
$validStatuses = IncidentQueueQuery::STATUSES;
$validSeverities = IncidentQueueQuery::SEVERITIES;
$selectedId = isset($_GET['id']) && is_scalar($_GET['id'])
    ? filter_var($_GET['id'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) : false;

$manager = new IncidentManager($pdo);
$repository = new IncidentRepository($pdo);
$error = null;
$rows = [];
$total = 0;
$detail = null;
$assignableUsers = [];
$caseNotes = ['notes'=>[], 'total'=>0, 'page'=>1, 'pages'=>1];
$notesPage = filter_var($_GET['notes_page'] ?? 1, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: 1;
$intelMatchesByIp = [];
$demoId = null;
try {
    $total = $repository->countIncidents($filters);
    $page = min($page, max(1, (int)ceil($total / 25)));
    $rows = $manager->listIncidents($filters, 25, ($page - 1) * 25);
    if ($selectedId !== false) {
        $detail = $manager->getIncident((int)$selectedId, 20);
        if (!empty($detail['is_simulated'])) {
            $demoStmt = $pdo->prepare('SELECT id FROM demo_sessions WHERE incident_id = ? LIMIT 1');
            $demoStmt->execute([$selectedId]); $demoId = $demoStmt->fetchColumn();
        }
        if ($detail !== null) $caseNotes = (new CaseNoteService($pdo))->list((int)$selectedId, $notesPage);
        if ($detail !== null) {
            $intelMatchesByIp = (new ThreatIntelMatcher($pdo))->matchSourceIps(
                array_column($detail['alerts'], 'source_ip')
            );
        }
        if ($detail !== null && $canAssign) {
            $accounts = $pdo->query('SELECT id, username, role FROM users ORDER BY username LIMIT 500')->fetchAll();
            foreach ($accounts as $account) {
                if (SoarAuth::hasPermission(SoarAuth::resolveTier($account['role']), 'change_status_normal')) {
                    $assignableUsers[] = $account;
                }
            }
        }
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
.brand{color:var(--cyan);font-weight:800;letter-spacing:1.2px;font-size:19px;text-decoration:none}nav{display:flex;gap:18px;flex-wrap:wrap}main{max-width:1180px;margin:auto;padding:25px 20px 60px}
h1{margin:0;font-size:29px}h2{font-size:20px;margin:0 0 15px}.lead{color:var(--muted);margin:3px 0 25px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px;margin:16px 0}
form{display:flex;align-items:end;flex-wrap:wrap;gap:15px}.field{display:flex;flex-direction:column;gap:4px}.field label{color:var(--muted);font-size:12px}
select,button,textarea,input[type="search"]{border:1px solid #376285;color:var(--text);background:#0d2541;padding:9px 12px;border-radius:6px;font:inherit}
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
<header><a class="brand" href="dashboard.php">THREATPULSE / SOC</a><nav><a href="dashboard.php">SIEM Dashboard</a><a href="incidents.php" aria-current="page">Incidents</a><a href="control_plane/index.php">SOAR Control Plane</a><a href="notifications.php">My inbox</a></nav></header>
<main>
<h1>Incident queue</h1>
<p><a href="demo.php">Simulated incident walkthrough</a></p>
<p class="lead">Review correlated detections, attached SIEM alerts, and the investigation timeline. Status progression uses the permission-checked incident API. Host containment actions are never initiated here.</p>
<?php if ($error !== null): ?><section class="panel error" role="alert"><?= incidentEscape($error) ?></section><?php endif; ?>
<section class="panel">
<form method="get" action="incidents.php">
<div class="field"><label for="q">Incident number or title</label><input type="search" id="q" name="q" maxlength="200" value="<?= incidentEscape($query['q']) ?>" placeholder="Search cases"></div>
<div class="field"><label for="kind">Data</label><select id="kind" name="kind">
<?php foreach (['observed'=>'Real incidents', 'simulated'=>'Simulated incidents', 'all'=>'All incidents'] as $value=>$label): ?>
<option value="<?= $value ?>" <?= $kind === $value ? 'selected' : '' ?>><?= $label ?></option>
<?php endforeach; ?></select></div>
<div class="field"><label for="status">Status</label><select id="status" name="status"><option value="">All statuses</option>
<?php foreach ($validStatuses as $choice): ?><option value="<?= incidentEscape($choice) ?>" <?= $status === $choice ? 'selected' : '' ?>><?= incidentEscape($choice) ?></option><?php endforeach; ?></select></div>
<div class="field"><label for="severity">Severity</label><select id="severity" name="severity"><option value="">All severities</option>
<?php foreach ($validSeverities as $choice): ?><option value="<?= incidentEscape($choice) ?>" <?= $severity === $choice ? 'selected' : '' ?>><?= incidentEscape($choice) ?></option><?php endforeach; ?></select></div>
<?php
$queueChoices = [
    'lifecycle'=>['Case state', ['all'=>'All states','active'=>'Active cases','finished'=>'Resolved / closed']],
    'priority'=>['Priority', [''=>'All priorities','P1'=>'P1','P2'=>'P2','P3'=>'P3','P4'=>'P4']],
    'owner'=>['Assignment', ['any'=>'Anyone','unassigned'=>'Unassigned'] + ($myUserId ? ['mine'=>'Assigned to me'] : [])],
    'stale_days'=>['Last case update', [''=>'Any time','1'=>'At least 1 day ago','3'=>'At least 3 days ago','7'=>'At least 7 days ago','30'=>'At least 30 days ago']],
    'sort'=>['Sort by', ['priority'=>'Priority first','newest'=>'Newest first','oldest'=>'Oldest first','least_updated'=>'Least recently updated']],
];
foreach ($queueChoices as $key=>[$label,$choices]): ?>
<div class="field"><label for="<?= $key ?>"><?= $label ?></label><select id="<?= $key ?>" name="<?= $key ?>">
<?php foreach ($choices as $value=>$text): ?><option value="<?= incidentEscape($value) ?>" <?= $query[$key] === (string)$value ? 'selected' : '' ?>><?= incidentEscape($text) ?></option><?php endforeach; ?>
</select></div>
<?php endforeach; ?>
<button type="submit">Apply filters</button><a href="incidents.php">Clear</a>
</form>
<p class="muted">Filters combine. Active includes new, open, investigating and contained cases. Last case update measures the case record, not every note, event or playbook action; it is not an SLA deadline.</p>
<p><a href="<?= incidentEscape(incidentUrl(['kind'=>$kind,'lifecycle'=>'active','owner'=>'unassigned'])) ?>">Unassigned active cases</a> · <a href="<?= incidentEscape(incidentUrl(['kind'=>$kind,'lifecycle'=>'active','stale_days'=>'7','sort'=>'least_updated'])) ?>">Active cases unchanged for 7+ days</a></p>
</section>
<section class="panel">
<div class="metrics"><span class="metric"><?= incidentEscape($total) ?></span><span class="muted">matching incidents · showing up to 25 per page</span></div>
<div class="table-scroll"><table><thead><tr><th>Incident</th><th>Title</th><th>Severity</th><th>Status</th><th>Priority</th><th>Assigned to</th><th>Alerts</th><th>Created / last case update</th></tr></thead><tbody>
<?php foreach ($rows as $incident): ?>
<tr>
<td><a href="<?= incidentEscape(incidentUrl(array_merge($query, ['id'=>$incident['id'], 'page'=>$page]))) ?>"><?= incidentEscape($incident['incident_number']) ?></a></td>
<td><?= incidentEscape($incident['title']) ?><?php if (!empty($incident['is_simulated'])): ?><br><strong>SIMULATED</strong><?php endif; ?></td>
<td><span class="pill <?= incidentEscape($incident['severity']) ?>"><?= incidentEscape($incident['severity']) ?></span></td>
<td><?= incidentEscape($incident['status']) ?></td>
<td><?= incidentEscape($incident['priority']) ?></td>
<td><?= incidentEscape($incident['assigned_username'] ?? 'Unassigned') ?></td>
<td><?= incidentEscape($incident['alert_count']) ?></td>
<td class="muted"><?= incidentEscape($incident['created_at']) ?><br>Updated <?= incidentEscape($incident['updated_at']) ?></td>
</tr>
<?php endforeach; ?>
<?php if (!$rows): ?><tr><td colspan="8" class="muted">No incidents match these filters.</td></tr><?php endif; ?>
</tbody></table></div>
<div class="pager"><span class="muted">Page <?= incidentEscape($page) ?> of <?= incidentEscape(max(1,(int)ceil($total/25))) ?></span>
<div>
<?php if ($page > 1): ?><a href="<?= incidentEscape(incidentUrl(array_merge($query, ['page'=>$page-1]))) ?>">Previous</a><?php endif; ?>
<?php if ($page * 25 < $total): ?><a href="<?= incidentEscape(incidentUrl(array_merge($query, ['page'=>$page+1]))) ?>">Next</a><?php endif; ?>
</div></div>
</section>
<?php if ($selectedId !== false): ?>
<section class="panel" id="details">
<h2><?= $detail ? incidentEscape($detail['incident_number']) . ' · ' . incidentEscape($detail['title']) : 'Incident not found' ?></h2>
<?php if ($detail): ?>
<?php if (!empty($detail['is_simulated'])): ?><p class="error"><strong>SIMULATED TEST DATA</strong> — investigation practice only. All playbooks are forced to dry-run. Live enrichment is disabled.</p><?php endif; ?>
<?php if ($demoId): ?><p><a href="demo.php?id=<?= (int)$demoId ?>">Continue the simulated walkthrough</a></p><?php endif; ?>
<div class="info-grid">
<div><strong>Status</strong><?= incidentEscape($detail['status']) ?></div>
<div><strong>Case handoff</strong><a href="incident-report.php?id=<?= (int)$detail['id'] ?>">Print or download an incident report</a></div>
<div><strong>Case indicators</strong><a href="incident-iocs.php?id=<?= (int)$detail['id'] ?>">Inspect indicators and saved intelligence</a></div>
<div><strong>SOAR workflows</strong><a href="incident-playbooks.php?id=<?= (int)$detail['id'] ?>">Inspect playbooks and run history</a></div>
<div><strong>Risk assessment</strong><a href="incident-risk.php?id=<?= (int)$detail['id'] ?>">View score explanation and history</a></div>
<div><strong>Severity / Priority</strong><?= incidentEscape($detail['severity']) ?> / <?= incidentEscape($detail['priority']) ?></div>
<div><strong>Attack category</strong><?= incidentEscape($detail['attack_category'] ?: 'Unclassified') ?></div>
<div><strong>Assigned analyst</strong><?= incidentEscape($detail['assigned_username'] ?: 'Unassigned') ?></div>
</div>
<?php if ($triageTransitions): ?>
<div class="triage">
<h2>Analyst triage</h2>
<p>Choose a permitted next state and record a reason. Status changes are checked against the state shown here. Repeating a completed change adds no duplicate history. This does not execute containment or host actions.</p>
<form id="triage-form" data-incident-id="<?= incidentEscape($detail['id']) ?>" data-current-status="<?= incidentEscape($detail['status']) ?>">
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
<?php if ($canAssign && $assignableUsers): ?>
<div class="triage">
<h2>Case assignment</h2>
<p>Assign responsibility to an eligible analyst. A changed assignment sends one in-app inbox notification to the new owner; assigning the current owner again makes no changes.</p>
<form id="assignment-form" data-incident-id="<?= incidentEscape($detail['id']) ?>" data-assigned-to="<?= incidentEscape($detail['assigned_to'] ?? '') ?>">
<input type="hidden" name="csrf_token" value="<?= incidentEscape($csrfToken) ?>">
<div class="field"><label for="assigned-analyst">Assign to</label><select id="assigned-analyst" name="analyst_id" required>
<?php foreach ($assignableUsers as $account): ?>
<option value="<?= incidentEscape($account['id']) ?>" <?= (int)($detail['assigned_to'] ?? 0) === (int)$account['id'] ? 'selected' : '' ?>><?= incidentEscape($account['username']) ?> (<?= incidentEscape($account['role']) ?>)</option>
<?php endforeach; ?>
</select></div>
<button type="submit">Assign case</button>
</form>
<div id="assignment-feedback" class="triage-feedback" role="status" aria-live="polite"></div>
</div>
<?php endif; ?>
<section class="triage" id="case-notes" aria-labelledby="case-notes-title">
<h2 id="case-notes-title">Case notes (<?= incidentEscape($caseNotes['total']) ?>)</h2>
<p>Append investigation findings and handoff context. Notes preserve their author and timeline entry; adding a note does not change case status or execute a response.</p>
<?php if ($canNote): ?>
<form id="case-note-form" data-incident-id="<?= incidentEscape($detail['id']) ?>">
<input type="hidden" name="csrf_token" value="<?= incidentEscape($csrfToken) ?>">
<div class="field" style="width:100%"><label for="case-note-text">Investigation note · maximum 10,000 UTF-8 bytes</label>
<textarea id="case-note-text" name="note" rows="4" maxlength="10000" required style="width:100%;resize:vertical"></textarea></div>
<button type="submit">Add case note</button></form>
<div id="case-note-feedback" class="triage-feedback" role="status" aria-live="polite"></div>
<?php else: ?><p>Sign in with a named user account to add a note.</p><?php endif; ?>
<?php foreach ($caseNotes['notes'] as $note): ?><article class="event"><strong><?= incidentEscape($note['author']) ?></strong><small>Note #<?= incidentEscape($note['id']) ?> · <?= incidentEscape($note['created_at']) ?> (server time)</small><pre><?= incidentEscape($note['note_text']) ?></pre></article><?php endforeach; ?>
<?php if (!$caseNotes['notes']): ?><p class="muted">No case notes yet. Record what you checked, what you found, and the next investigation step.</p><?php endif; ?>
<?php if ($caseNotes['pages'] > 1): ?><div class="pager"><span>Notes page <?= incidentEscape($caseNotes['page']) ?> of <?= incidentEscape($caseNotes['pages']) ?></span><span>
<?php if ($caseNotes['page'] > 1): ?><a href="<?= incidentEscape(incidentUrl(array_merge($query, ['page'=>$page, 'id'=>$detail['id'], 'notes_page'=>$caseNotes['page']-1]))) ?>#case-notes">Newer notes</a><?php endif; ?>
<?php if ($caseNotes['page'] < $caseNotes['pages']): ?><a href="<?= incidentEscape(incidentUrl(array_merge($query, ['page'=>$page, 'id'=>$detail['id'], 'notes_page'=>$caseNotes['page']+1]))) ?>#case-notes">Older notes</a><?php endif; ?>
</span></div><?php endif; ?>
</section>
<h2>Description</h2><pre><?= incidentEscape($detail['description']) ?></pre>
<h2>Linked SIEM alerts (<?= count($detail['alerts']) ?>)</h2>
<?php if (!$detail['is_simulated']): ?><p><a href="incident-evidence.php?id=<?= (int)$detail['id'] ?>">Find and link preserved event evidence</a></p><?php endif; ?>
<?php foreach ($detail['alerts'] as $alert): ?>
<div class="event">
    <strong><?= incidentEscape($alert['category']) ?> · <?= incidentEscape($alert['severity']) ?></strong>
    <small><?= incidentEscape($alert['event_timestamp']) ?> · Source <?= incidentEscape($alert['source_ip']) ?> · <a href="events.php?log_id=<?= incidentEscape($alert['log_id']) ?>#evidence">Log #<?= incidentEscape($alert['log_id']) ?> · inspect evidence</a></small>
    <pre><?= incidentEscape($alert['message']) ?></pre>
    <?php $intelListings = $intelMatchesByIp[$alert['source_ip'] ?? ''] ?? []; ?>
    <?php if ($intelListings): ?>
    <div style="border-top:1px solid #25506a;padding-top:10px;margin-top:10px">
        <strong style="color:#6cdecd">External threat-intelligence matches (<?= count($intelListings) ?>)</strong>
        <p class="muted" style="margin:5px 0 10px">These are public reputation listings for this source IP, not proof that this event was malicious.</p>
        <?php foreach ($intelListings as $listing): ?>
        <div style="padding:7px 0">
            <strong><?= incidentEscape(str_replace('_', ' ', $listing['provider'])) ?></strong>
            · <?= incidentEscape($listing['threat_type'] ?: 'Unclassified') ?>
            <?php if (!empty($listing['malware_family'])): ?> · <?= incidentEscape($listing['malware_family']) ?><?php endif; ?>
            <small>Source last seen: <?= incidentEscape($listing['source_last_seen'] ?: 'Not provided') ?> · Last imported (UTC): <?= incidentEscape($listing['fetched_at']) ?></small>
        </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
</div>
<?php endforeach; ?>
<?php if (!$detail['alerts']): ?><p class="muted">No linked SIEM logs.</p><?php endif; ?>
<h2 style="margin-top:20px">Recent investigation timeline</h2>
<p class="muted">Up to 20 latest entries, newest first (UTC). <a href="incident-timeline.php?id=<?= (int)$detail['id'] ?>">View and filter full history</a></p>
<?php foreach ($detail['timeline'] as $event): ?><div class="event"><strong><?= incidentEscape($event['event_type']) ?></strong><small><?= incidentEscape($event['created_at']) ?> · <?= incidentEscape($event['actor_name']) ?></small><?= incidentEscape($event['summary']) ?></div><?php endforeach; ?>
<?php if (!$detail['timeline']): ?><p class="muted">No timeline entries yet.</p><?php endif; ?>
<?php endif; ?>
</section>
<?php endif; ?>
</main>
<script>
(function () {
    const form = document.getElementById('triage-form');
    if (form) {
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
                    expected_status: form.dataset.currentStatus,
                    reason: reason
                })
            });
            const result = await response.json();
            if (!response.ok || result.success !== true) {
                feedback.textContent = result.message || 'Status update failed. Please retry.';
                if (response.status === 409) {
                    const reload = document.createElement('a');
                    reload.href = window.location.href;
                    reload.textContent = 'Reload case';
                    feedback.append(' ', reload);
                }
                return;
            }
            window.location.reload();
        } catch (_) {
            feedback.textContent = 'Could not contact the incident API. Please retry.';
        } finally {
            button.disabled = false;
        }
    });
    }

    const assignment = document.getElementById('assignment-form');
    if (assignment) {
        const assignmentFeedback = document.getElementById('assignment-feedback');
        assignment.addEventListener('submit', async function (event) {
            event.preventDefault();
            const data = new FormData(assignment);
            const analystId = Number(data.get('analyst_id'));
            if (!Number.isSafeInteger(analystId) || analystId <= 0) {
                assignmentFeedback.textContent = 'Choose a valid analyst.';
                return;
            }
            const button = assignment.querySelector('button[type="submit"]');
            button.disabled = true;
            assignmentFeedback.textContent = 'Assigning case...';
            try {
                const response = await fetch('api/v1/incidents_detail.php', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': String(data.get('csrf_token') || '')
                    },
                    body: JSON.stringify({
                        id: Number(assignment.dataset.incidentId),
                        action: 'assign',
                        analyst_id: analystId,
                        expected_assigned_to: assignment.dataset.assignedTo === '' ? null : Number(assignment.dataset.assignedTo)
                    })
                });
                const result = await response.json();
                if (!response.ok || result.success !== true) {
                    assignmentFeedback.textContent = result.message || 'Case assignment failed.';
                    return;
                }
                window.location.reload();
            } catch (_) {
                assignmentFeedback.textContent = 'Could not contact the incident API. Please retry.';
            } finally {
                button.disabled = false;
            }
        });
    }
})();
</script>
<script src="assets/js/case-notes.js" defer></script>
</body>
</html>
