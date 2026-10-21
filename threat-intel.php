<?php
/** ThreatPulse threat intelligence inventory: external indicators, not detections. */
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
    exit('Not authorized to view threat intelligence.');
}
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header_remove('X-Powered-By');

function intelEscape(mixed $value): string {
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

$page = max(1, min(1000, (int)($_GET['page'] ?? 1)));
$limit = 30;
$offset = ($page - 1) * $limit;
$total = 0;
$rows = [];
$lastFetched = null;
$providerCounts = [];
$error = null;
$available = false;
try {
    $available = (int)$pdo->query("SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'threat_feed_indicators'")->fetchColumn() === 1;
    if ($available) {
        $total = (int)$pdo->query('SELECT COUNT(*) FROM threat_feed_indicators')->fetchColumn();
        $lastFetched = $pdo->query('SELECT MAX(fetched_at) FROM threat_feed_indicators')->fetchColumn();
        $providerCounts = $pdo->query('SELECT provider, COUNT(*) AS total FROM threat_feed_indicators GROUP BY provider ORDER BY total DESC')->fetchAll(PDO::FETCH_ASSOC);
        $stmt = $pdo->prepare("SELECT provider, indicator_type, indicator_value, threat_type,
            malware_family, port, source_last_seen, fetched_at
            FROM threat_feed_indicators ORDER BY fetched_at DESC, id DESC LIMIT ? OFFSET ?");
        $stmt->bindValue(1, $limit, PDO::PARAM_INT);
        $stmt->bindValue(2, $offset, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
} catch (Throwable $e) {
    error_log('Threat intelligence inventory failed: ' . $e->getMessage());
    $error = 'Threat intelligence is temporarily unavailable.';
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse | Threat Intelligence</title>
<style>
:root{color-scheme:dark;--bg:#090f19;--panel:#101b2b;--line:#283a50;--text:#edf4fc;--muted:#9eafc3;--accent:#52cbb2}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
a{color:#8cddda;text-decoration:none}a:hover{text-decoration:underline}
.layout{min-height:100vh;display:grid;grid-template-columns:220px minmax(0,1fr)}
aside{background:#0e1827;border-right:1px solid var(--line);padding:26px 16px;display:flex;flex-direction:column;gap:30px}
.brand{font-size:20px;font-weight:750;letter-spacing:-.5px;color:var(--text);padding:0 10px}
nav{display:flex;flex-direction:column;gap:5px}
nav a{color:#b9c9da;padding:11px 12px;border-radius:9px}
nav a[aria-current=page]{color:#c9fff1;background:#203a46;font-weight:700}nav a:hover{background:#1a2a3c;text-decoration:none}
main{padding:30px clamp(18px,3vw,54px) 60px;max-width:1500px;width:100%;margin:auto;min-width:0}
.eyebrow{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--accent);font-weight:750}
h1{font-size:32px;letter-spacing:-.7px;margin:6px 0 5px}p{color:var(--muted);margin:5px 0 20px}
.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:23px 0}
.card,.panel{border:1px solid var(--line);background:var(--panel);border-radius:13px;padding:21px}
.label{font-size:12px;color:var(--muted)}.value{font-size:30px;letter-spacing:-.5px;font-weight:750;margin-top:5px}
.panel{overflow:hidden}.panel-header{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:15px}
h2{margin:0;font-size:17px}.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;color:#8fa3b9;text-transform:uppercase;letter-spacing:.8px}
th,td{padding:12px 9px;border-bottom:1px solid #27374b;vertical-align:top}
td{color:#d9e8f5;overflow-wrap:anywhere}
code{color:#b6d8e8;font-size:12px}
.badge{display:inline-block;padding:4px 8px;border:1px solid #42685e;border-radius:20px;color:#b8ece2;font-size:11px;font-weight:700}
.notice{padding:13px 16px;background:#25291c;border:1px solid #555c39;border-radius:9px;color:#e6dbb5;font-size:13px}
.error{color:#f7c5c7;background:#361f28;border-color:#91565b}
.pages{display:flex;justify-content:space-between;gap:12px;margin-top:18px;align-items:center;color:var(--muted)}
.pages a{padding:8px 14px;border:1px solid var(--line);border-radius:7px}
@media(max-width:720px){.layout{display:block}aside{padding:15px;gap:14px;border-right:0;border-bottom:1px solid var(--line)}nav{flex-direction:row;overflow:auto}nav a{white-space:nowrap;padding:8px}main{padding:23px 15px}h1{font-size:26px}.cards{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="layout">
<aside>
  <a class="brand" href="soc.php">ThreatPulse</a>
  <nav aria-label="SOC navigation">
    <a href="soc.php">Overview</a>
    <a href="events.php">Event evidence</a>
      <a href="dashboard.php">Legacy SIEM</a>
    <a href="threat-intel.php" aria-current="page">Threat intelligence</a>
    <a href="feeds.php">Feed health</a><a href="incidents.php">Incidents</a>
    <a href="control_plane/index.php">SOAR approvals</a>
  </nav>
</aside>
<main>
  <span class="eyebrow">Intelligence / External indicators</span>
  <h1>Threat intelligence</h1>
  <p>Explore reported malicious infrastructure from connected external sources. These indicators are not confirmed incidents in your environment.</p>
  <?php if ($error !== null): ?><div class="notice error" role="alert"><?= intelEscape($error) ?></div><?php endif; ?>
  <?php if (!$available): ?>
    <div class="notice">The threat-intelligence inventory is not initialized. Apply <code>database/migrations/007_threat_feed_indicators.sql</code> to this database.</div>
  <?php else: ?>
  <div class="cards">
    <div class="card"><div class="label">Known external indicators</div><div class="value"><?= intelEscape(number_format($total)) ?></div></div>
    <div class="card"><div class="label">Last stored refresh (UTC)</div><div class="value" style="font-size:23px"><?= intelEscape($lastFetched ?: 'No imports yet') ?></div></div>
  </div>
  <div class="notice">Source: external feed listings. Do not interpret these IPs as attackers observed by a local SIEM sensor. Refresh time reflects stored data, not guaranteed feed availability. <a href="feeds.php">View collection health and history.</a></div>
  <section class="panel" style="margin-top:19px" aria-labelledby="providers-title"><h2 id="providers-title">Connected intelligence sources</h2>
  <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:14px">
    <?php foreach ($providerCounts as $source): ?><span class="badge"><?= intelEscape(str_replace('_', ' ', $source['provider'])) ?> · <?= intelEscape(number_format((int)$source['total'])) ?></span><?php endforeach; ?>
    <?php if (!$providerCounts): ?><span style="color:var(--muted)">No feeds imported yet.</span><?php endif; ?>
  </div></section>
  <section class="panel" style="margin-top:19px" aria-labelledby="indicator-title">
    <div class="panel-header"><h2 id="indicator-title">Indicator inventory</h2><span class="badge">Multi-source inventory</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>Indicator</th><th>Source</th><th>Classification</th><th>Malware</th><th>Port</th><th>Source last seen</th></tr></thead>
      <tbody>
      <?php foreach ($rows as $row): ?>
        <tr>
          <td><code><?= intelEscape($row['indicator_value']) ?></code><br><span class="badge"><?= intelEscape($row['indicator_type']) ?></span></td>
          <td><?= intelEscape($row['provider']) ?></td>
          <td><?= intelEscape($row['threat_type'] ?: 'Unknown') ?></td>
          <td><?= intelEscape($row['malware_family'] ?: 'Unknown') ?></td>
          <td><?= intelEscape($row['port'] ?: '—') ?></td>
          <td><?= intelEscape($row['source_last_seen'] ?: 'Not provided') ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$rows): ?><tr><td colspan="6" style="color:var(--muted);padding:30px;text-align:center">No indicators imported yet. Run the Feodo collector after applying migration 007.</td></tr><?php endif; ?>
      </tbody>
    </table></div>
    <div class="pages">
      <span>Page <?= intelEscape($page) ?> of <?= intelEscape(max(1, (int)ceil($total / $limit))) ?></span>
      <span>
        <?php if ($page > 1): ?><a href="threat-intel.php?page=<?= intelEscape($page - 1) ?>">Previous</a><?php endif; ?>
        <?php if ($page * $limit < $total): ?><a href="threat-intel.php?page=<?= intelEscape($page + 1) ?>">Next</a><?php endif; ?>
      </span>
    </div>
  </section>
  <?php endif; ?>
</main>
</div>
</body>
</html>
