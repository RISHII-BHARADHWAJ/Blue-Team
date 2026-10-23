<?php
/**
 * ThreatPulse SOC overview.
 * Read-only operational landing page; does not infer attacks from feed indicators.
 */
declare(strict_types=1);

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/soar/SoarAuth.php';

$auth = SoarAuth::getContext($pdo);
if ($auth['actor'] === 'anonymous') {
    header('Location: login.php');
    exit;
}
if (!SoarAuth::hasPermission($auth['tier'], 'view_incidents')) {
    http_response_code(403);
    exit('Not authorized to view the SOC workspace.');
}
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header_remove('X-Powered-By');

function socEscape(mixed $value): string {
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$metrics = ['records' => 0, 'sources' => 0, 'critical' => 0, 'high' => 0];
$severities = [];
$recent = [];
$incidentCount = null;
$incidentRows = [];
$dbError = null;
try {
    $summary = $pdo->query("SELECT COUNT(*) AS records, COUNT(DISTINCT source_ip) AS sources,
        COALESCE(SUM(severity = 'CRITICAL'),0) AS critical,
        COALESCE(SUM(severity = 'HIGH'),0) AS high FROM logs")->fetch(PDO::FETCH_ASSOC);
    foreach ($metrics as $key => $_) $metrics[$key] = (int)($summary[$key] ?? 0);
    $severities = $pdo->query("SELECT severity, COUNT(*) AS n FROM logs GROUP BY severity ORDER BY FIELD(severity,'CRITICAL','HIGH','WARNING','INFO','LOW')")->fetchAll(PDO::FETCH_ASSOC);
    $recent = $pdo->query("SELECT timestamp, source_ip, severity, category, message
        FROM logs ORDER BY timestamp DESC, id DESC LIMIT 12")->fetchAll(PDO::FETCH_ASSOC);

    // The SOAR schema may not be present in a legacy/local database yet.
    $hasIncidents = $pdo->query("SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'incidents'")->fetchColumn();
    if ((int)$hasIncidents > 0) {
        $incidentCount = (int)$pdo->query("SELECT COUNT(*) FROM incidents WHERE is_simulated = 0 AND status NOT IN ('RESOLVED','CLOSED')")->fetchColumn();
        $incidentRows = $pdo->query("SELECT id, incident_number, title, severity, status, created_at
            FROM incidents WHERE is_simulated = 0 ORDER BY created_at DESC, id DESC LIMIT 6")->fetchAll(PDO::FETCH_ASSOC);
    }
} catch (Throwable $e) {
    error_log('SOC overview query failed: ' . $e->getMessage());
    $dbError = 'Some SOC data is currently unavailable. Check the database schema and service logs.';
}

$feedSources=[]; $feedError=null;
try {
    require_once __DIR__ . '/includes/intel/FeedRepository.php';
    $feedSources=(new FeedRepository($pdo))->sources();
} catch (Throwable $e) { $feedError='Feed history unavailable; check migration 010 and database health.'; }

$severityColors = [
    'CRITICAL' => '#ef6978', 'HIGH' => '#f3a75e', 'WARNING' => '#f4cb6b',
    'INFO' => '#6cbbec', 'LOW' => '#54c5aa',
];
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>ThreatPulse | SOC Overview</title>
<style>
:root{color-scheme:dark;--bg:#090f19;--panel:#101b2b;--panel2:#152237;--line:#283a50;--text:#edf4fc;--muted:#9eafc3;--accent:#52cbb2}
*{box-sizing:border-box}
body{margin:0;color:var(--text);background:var(--bg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:#8cddda;text-decoration:none}a:hover{text-decoration:underline}
.shell{min-height:100vh;display:grid;grid-template-columns:222px minmax(0,1fr)}
aside{border-right:1px solid var(--line);background:#0e1827;padding:26px 16px;display:flex;flex-direction:column;gap:28px}
.brand{display:flex;align-items:center;gap:10px;padding:0 10px;font-weight:750;font-size:20px;letter-spacing:-.6px;color:var(--text)}
.logo{width:33px;height:33px;display:grid;place-items:center;background:#1d594e;color:#a7ffe6;border-radius:10px;font-size:20px}
.nav-title{font-size:11px;color:#8498ae;text-transform:uppercase;letter-spacing:1.5px;padding:0 12px;margin-bottom:9px}
.nav{display:flex;flex-direction:column;gap:5px}
.nav a{display:block;color:#b9c9da;padding:11px 12px;border-radius:9px}
.nav a[aria-current=page]{background:#203a46;color:#c9fff1;font-weight:700}
.nav a:hover{background:#1a2a3c;text-decoration:none}
.sidebar-foot{font-size:12px;color:var(--muted);margin-top:auto;border-top:1px solid var(--line);padding:16px 10px}
main{min-width:0;padding:30px clamp(18px,3.2vw,54px) 64px;max-width:1570px;width:100%;margin:auto}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:27px}
.eyebrow{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--accent);font-weight:700}
h1{font-size:32px;letter-spacing:-.9px;margin:5px 0 4px}h2{font-size:17px;letter-spacing:-.25px;margin:0}
p{margin:5px 0;color:var(--muted)}
.user{color:var(--muted);font-size:13px;text-align:right}
.pill{font-size:11px;font-weight:750;padding:5px 9px;border:1px solid #3f6170;color:#90dfd1;border-radius:30px;white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}
.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:13px}
.card{padding:19px 21px}
.card .label{font-size:12px;color:var(--muted);font-weight:600}
.number{font-size:34px;font-weight:750;letter-spacing:-1.2px;font-variant-numeric:tabular-nums;margin-top:7px}
.card .note{font-size:12px;color:#8297ad;margin-top:5px}
.columns{display:grid;grid-template-columns:minmax(0,1.7fr) minmax(280px,1fr);gap:16px;margin-top:19px}
.panel{padding:21px;min-width:0}
.panel-head{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:14px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{font-weight:650;color:#8fa3b9;font-size:11px;letter-spacing:.7px;text-transform:uppercase;text-align:left}
th,td{padding:12px 8px;border-bottom:1px solid #253449;vertical-align:top}
td{color:#d8e7f5}td.message{min-width:240px;max-width:420px;overflow-wrap:anywhere}
code{font-size:12px;color:#abd2e1}
.tag{display:inline-block;font-size:11px;border-radius:5px;background:#243346;padding:3px 7px;color:#dfebf7;font-weight:750}
.empty{padding:32px 10px;text-align:center;color:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:11px;margin:15px 0 12px}
.legend span{color:#bdcedf;font-size:12px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.track{display:flex;width:100%;height:12px;background:#243247;border-radius:6px;overflow:hidden}
.track span{height:100%;display:block}
.divider{height:1px;background:var(--line);margin:21px 0}
.fact{display:flex;justify-content:space-between;gap:10px;padding:10px 0}
.fact b{font-weight:650}.fact span{color:var(--muted);text-align:right}
.callout{border:1px solid #4b5635;background:#25291c;color:#e8d7a3;padding:13px 16px;border-radius:9px;font-size:12px;margin:21px 0}
.error{border-color:#91565b;background:#361f28;color:#f8c5c9}
.action{display:inline-block;padding:9px 13px;border-radius:8px;background:#254e4b;color:#cffbef;font-size:12px;font-weight:750}
.action:hover{background:#32655e;text-decoration:none}
@media(max-width:1060px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.columns{grid-template-columns:1fr}}
@media(max-width:700px){.shell{display:block}aside{gap:10px;padding:12px;border-right:0;border-bottom:1px solid var(--line)}.brand{font-size:17px}.nav-title,.sidebar-foot{display:none}.nav{flex-direction:row;overflow:auto}.nav a{white-space:nowrap;padding:7px 10px}main{padding:24px 14px}.top{flex-direction:column;gap:9px}.user{text-align:left}h1{font-size:26px}}
</style>
</head>
<body>
<div class="shell">
<aside>
  <a href="soc.php" class="brand"><span class="logo">T</span> ThreatPulse</a>
  <div>
    <div class="nav-title">Workspace</div>
    <nav class="nav" aria-label="Main navigation">
      <a href="soc.php" aria-current="page">Overview</a>
      <a href="events.php">Event evidence</a>
      <a href="dashboard.php">Legacy SIEM</a>
      <a href="detections.php">Detections</a><a href="threat-intel.php">Threat intelligence</a>
      <a href="feeds.php">Feed health</a><a href="incidents.php">Incidents</a>
      <a href="control_plane/index.php">SOAR approvals</a>
      <a href="notifications.php">My inbox</a>
    </nav>
  </div>
  <div class="sidebar-foot">Development environment<br>Read-only SOC overview</div>
</aside>
<main>
  <div class="top">
    <div><span class="eyebrow">Security operations / overview</span>
      <h1>Security workspace</h1>
      <p>Investigate recorded telemetry, threat-feed entries, and analyst cases.</p>
    </div>
    <div class="user">Signed in as <?= socEscape($auth['actor']) ?><br><span class="pill"><?= socEscape($auth['tier']) ?></span></div>
  </div>

  <?php if ($dbError !== null): ?><div class="callout error" role="alert"><?= socEscape($dbError) ?></div><?php endif; ?>
  <div class="cards">
    <div class="card"><div class="label">Stored SIEM records</div><div class="number"><?= socEscape(number_format($metrics['records'])) ?></div><div class="note">Includes imported threat feeds</div></div>
    <div class="card"><div class="label">Distinct source IPs</div><div class="number"><?= socEscape(number_format($metrics['sources'])) ?></div><div class="note">Across stored records</div></div>
    <div class="card"><div class="label">Critical-labelled records</div><div class="number"><?= socEscape(number_format($metrics['critical'])) ?></div><div class="note">Not necessarily local attacks</div></div>
    <div class="card"><div class="label">Active incidents</div><div class="number"><?= $incidentCount === null ? '—' : socEscape(number_format($incidentCount)) ?></div><div class="note"><?= $incidentCount === null ? 'SOAR schema not initialized' : 'Not resolved or closed' ?></div></div>
  </div>
  <div class="callout"><strong>Data provenance:</strong> The legacy <code>logs</code> table mixes local telemetry and external blocklist indicators. A feed listing does not prove an attack against your environment. Source separation is planned.</div>

  <div class="columns">
    <section class="panel" aria-labelledby="recent-title">
      <div class="panel-head"><h2 id="recent-title">Latest records</h2><a class="action" href="dashboard.php">Explore SIEM →</a></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Time</th><th>Severity</th><th>Source IP</th><th>Details</th></tr></thead>
        <tbody>
        <?php foreach ($recent as $event): ?>
        <tr>
          <td><?= socEscape($event['timestamp']) ?></td>
          <td><span class="tag"><?= socEscape($event['severity']) ?></span></td>
          <td><code><?= socEscape($event['source_ip']) ?></code></td>
          <td class="message"><?= socEscape($event['message']) ?></td>
        </tr>
        <?php endforeach; ?>
        <?php if (!$recent): ?><tr><td colspan="4" class="empty">No records yet. Check feed ingestion or connect a sensor.</td></tr><?php endif; ?>
        </tbody>
      </table></div>
    </section>
    <div>
      <section class="panel" aria-labelledby="feed-title">
        <div class="panel-head"><h2 id="feed-title">Feed health</h2><a href="feeds.php">Collection history →</a></div>
        <?php if ($feedError): ?><p><?= socEscape($feedError) ?></p><?php endif; ?>
        <?php if (getenv('FEED_COLLECTION_ENABLED')==='0'): ?><p>Collection paused by deployment setting.</p><?php endif; ?>
        <?php foreach ($feedSources as $feed): ?>
          <div class="fact"><b><?= socEscape(FeedCatalog::FEEDS[$feed['provider']]['name']??$feed['provider']) ?></b><span><?= socEscape($feed['health']) ?><br><?= socEscape($feed['last_attempt_at']??'Never attempted') ?></span></div>
        <?php endforeach; ?>
        <p>Status reflects recorded collection results, not confirmation of local attacks.</p>
        <div class="divider"></div>
        <h2>Severity distribution</h2>
        <?php if ($metrics['records'] > 0): ?>
          <div class="legend">
            <?php foreach ($severities as $entry): ?>
              <span><i class="dot" style="background:<?= socEscape($severityColors[$entry['severity']] ?? '#a4b5c5') ?>"></i><?= socEscape($entry['severity']) ?> <?= socEscape($entry['n']) ?></span>
            <?php endforeach; ?>
          </div>
          <div class="track" role="img" aria-label="Proportion of records by severity">
            <?php foreach ($severities as $entry): ?>
              <span style="width:<?= socEscape(number_format((int)$entry['n'] / $metrics['records'] * 100, 2, '.', '')) ?>%;background:<?= socEscape($severityColors[$entry['severity']] ?? '#a4b5c5') ?>"></span>
            <?php endforeach; ?>
          </div>
        <?php else: ?><p>No records to chart.</p><?php endif; ?>
      </section>
      <section class="panel" aria-labelledby="case-title" style="margin-top:16px">
        <div class="panel-head"><h2 id="case-title">Latest incidents</h2><a href="incidents.php">Open queue →</a></div>
        <?php if ($incidentCount === null): ?>
          <p>The SOAR database migrations have not been applied to this database.</p>
        <?php elseif (!$incidentRows): ?>
          <p>No incidents yet. Imported feed entries are not automatically evidence of a local incident.</p>
        <?php else: ?>
          <?php foreach ($incidentRows as $incident): ?>
            <div class="fact">
              <b><a href="incidents.php?id=<?= socEscape((int)$incident['id']) ?>"><?= socEscape($incident['incident_number']) ?></a><br><span style="color:var(--muted);font-weight:400"><?= socEscape($incident['title']) ?></span></b>
              <span><?= socEscape($incident['status']) ?><br><?= socEscape($incident['severity']) ?></span>
            </div>
          <?php endforeach; ?>
        <?php endif; ?>
      </section>
    </div>
  </div>
</main>
</div>
</body>
</html>
