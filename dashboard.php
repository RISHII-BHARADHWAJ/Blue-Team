<?php
session_name('CYBERTECH_SECURE_SESSION');
session_start(['cookie_httponly'=>true,'cookie_samesite'=>'Strict','use_strict_mode'=>true]);
if (empty($_SESSION['analyst'])) {
    header('Location: login.php');
    exit;
}

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header_remove('X-Powered-By');

if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['filter_submit'])) {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf'] ?? '')) { http_response_code(403); exit; }
    $allowed_time = ['all','today','week','month'];
    $allowed_sort = ['time_desc','time_asc','severity_desc','severity_asc'];
    $allowed_cat  = ['','SSH','SQLi','XSS','RCE','SSTI','LFI','Other'];
    $_SESSION['f_time'] = in_array($_POST['time'] ?? '', $allowed_time) ? $_POST['time'] : 'all';
    $_SESSION['f_sort'] = in_array($_POST['sort'] ?? '', $allowed_sort) ? $_POST['sort'] : 'time_desc';
    $_SESSION['f_cat']  = in_array($_POST['cat'] ?? '', $allowed_cat)  ? $_POST['cat']  : '';
    $_SESSION['f_ip']   = filter_var($_POST['ip'] ?? '', FILTER_VALIDATE_IP) ?: '';
    header('Location: dashboard.php'); exit;
}
if (isset($_GET['clear'])) {
    $_SESSION['f_time']='all'; $_SESSION['f_sort']='time_desc';
    $_SESSION['f_cat']=''; $_SESSION['f_ip']='';
    header('Location: dashboard.php'); exit;
}

$f_time = $_SESSION['f_time'] ?? 'all';
$f_sort = $_SESSION['f_sort'] ?? 'time_desc';
$f_cat  = $_SESSION['f_cat']  ?? '';
$f_ip   = $_SESSION['f_ip']   ?? '';

$db_host = getenv('DB_HOST') ? getenv('DB_HOST') : "localhost";
$pdo = new PDO("mysql:host=$db_host;dbname=cybertech_db;charset=utf8mb4", 'redteam_user', 'root', [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
]);

$where = ['1=1']; $params = [];
if ($f_time === 'today') { $where[] = 'DATE(timestamp) = CURDATE()'; } 
elseif ($f_time === 'week') { $where[] = 'timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)'; } 
elseif ($f_time === 'month') { $where[] = 'timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)'; }
if ($f_cat !== '') { $where[] = 'category = ?'; $params[] = $f_cat; }
if ($f_ip !== '') { $where[] = 'source_ip = ?'; $params[] = $f_ip; }
$whereSQL = implode(' AND ', $where);

$sortMap = [
    'time_desc' => 'timestamp DESC', 'time_asc' => 'timestamp ASC',
    'severity_desc' => "FIELD(severity, 'CRITICAL','HIGH','WARNING','INFO','LOW')",
    'severity_asc'  => "FIELD(severity, 'LOW','INFO','WARNING','HIGH','CRITICAL')"
];
$orderSQL = $sortMap[$f_sort] ?? 'timestamp DESC';

$alertCount = $pdo->prepare("SELECT COUNT(*) FROM logs WHERE $whereSQL"); $alertCount->execute($params); $alertCount = $alertCount->fetchColumn();
$attackerCount = $pdo->prepare("SELECT COUNT(DISTINCT source_ip) FROM logs WHERE $whereSQL"); $attackerCount->execute($params); $attackerCount = $attackerCount->fetchColumn();
$eventCount = $pdo->prepare("SELECT COUNT(*) FROM logs WHERE $whereSQL"); $eventCount->execute($params); $eventCount = $eventCount->fetchColumn();
// Count CRITICAL and HIGH alerts
$critQuery = $pdo->prepare("
    SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high
    FROM logs
    WHERE $whereSQL
");
$critQuery->execute($params);
$sevCounts = $critQuery->fetch();

$total    = max(1, $sevCounts['total']);
$critical = $sevCounts['critical'];
$high     = $sevCounts['high'];

// Weighted score: CRITICAL=2pts, HIGH=1pt, max=15
$score = (($critical * 2) + ($high * 1));
$threatLevel = min(15, (int)round($score / $total * 15));

$logQuery = $pdo->prepare("SELECT timestamp, severity, category, message, source_ip FROM logs WHERE $whereSQL ORDER BY $orderSQL LIMIT 200");
$logQuery->execute($params);
$logs = $logQuery->fetchAll();

$topAttackers = $pdo->query("
    SELECT source_ip, COUNT(*) as cnt
    FROM logs
    WHERE source_ip IS NOT NULL
      AND source_ip != ''
      AND source_ip != 'Unknown'
    GROUP BY source_ip
    ORDER BY cnt DESC
    LIMIT 10
")->fetchAll();
$maxAttacks = !empty($topAttackers) 
    ? $topAttackers[0]['cnt'] : 1;
$medals = ['#FFD700','#C0C0C0','#CD7F32'];

$catStats = $pdo->query("SELECT category, COUNT(*) as cnt FROM logs GROUP BY category ORDER BY cnt DESC")->fetchAll();
$maxCat = $catStats[0]['cnt'] ?? 1;

// Get attack dots — grouped by IP with coordinates
$mapDots = $pdo->query("
    SELECT 
        g.latitude,
        g.longitude,
        g.country_name,
        g.country_code,
        g.city,
        l.source_ip,
        COUNT(*) as alert_count
    FROM logs l
    JOIN ip_geo g ON l.source_ip = g.ip
    WHERE g.latitude IS NOT NULL
      AND g.longitude IS NOT NULL
      AND g.latitude != 0
      AND g.longitude != 0
    GROUP BY g.latitude, g.longitude, 
             g.country_name, g.country_code,
             g.city, l.source_ip
    ORDER BY alert_count DESC
    LIMIT 200
")->fetchAll();

// Country totals for pills bar
$mapCountries = $pdo->query("
    SELECT 
        g.country_code,
        g.country_name,
        COUNT(DISTINCT l.source_ip) as ip_count,
        COUNT(*) as alert_count
    FROM logs l
    JOIN ip_geo g ON l.source_ip = g.ip
    WHERE g.country_name IS NOT NULL
      AND g.country_name != ''
    GROUP BY g.country_code, g.country_name
    ORDER BY alert_count DESC
    LIMIT 12
")->fetchAll();

$mapMaxAlerts = !empty($mapDots) 
    ? $mapDots[0]['alert_count'] : 1;

$countryStats = $pdo->query("
    SELECT 
        g.country_code,
        g.country_name,
        COUNT(DISTINCT l.source_ip) as ip_count,
        COUNT(*) as alert_count
    FROM logs l
    JOIN ip_geo g ON l.source_ip = g.ip
    WHERE g.country_name IS NOT NULL
      AND g.country_name != ''
    GROUP BY g.country_code, g.country_name
    ORDER BY alert_count DESC
    LIMIT 12
")->fetchAll();

// Fallback if ip_geo is empty — show top IPs instead
if (empty($countryStats)) {
    $countryStats = [];
    $useIPFallback = true;
    $ipFallback = $pdo->query("
        SELECT source_ip, COUNT(*) as alert_count,
               1 as ip_count,
               '' as country_code,
               source_ip as country_name
        FROM logs
        WHERE source_ip IS NOT NULL
          AND source_ip != ''
          AND source_ip != 'Unknown'
        GROUP BY source_ip
        ORDER BY alert_count DESC
        LIMIT 12
    ")->fetchAll();
} else {
    $useIPFallback = false;
    $ipFallback = [];
}

$displayData = empty($countryStats) 
             ? $ipFallback 
             : $countryStats;
$maxStat = !empty($displayData) 
         ? $displayData[0]['alert_count'] : 1;

// Country flags map
$flags = [
    'CN'=>'🇨🇳','RU'=>'🇷🇺','US'=>'🇺🇸','DE'=>'🇩🇪',
    'NL'=>'🇳🇱','BR'=>'🇧🇷','IN'=>'🇮🇳','FR'=>'🇫🇷',
    'GB'=>'🇬🇧','KR'=>'🇰🇷','JP'=>'🇯🇵','SG'=>'🇸🇬',
    'VN'=>'🇻🇳','UA'=>'🇺🇦','ID'=>'🇮🇩','TR'=>'🇹🇷',
    'PK'=>'🇵🇰','OM'=>'🇴🇲','TW'=>'🇹🇼','CA'=>'🇨🇦',
    'HK'=>'🇭🇰','IR'=>'🇮🇷','RO'=>'🇷🇴','BG'=>'🇧🇬',
];

function getSevColor($sev) {
    return ['CRITICAL'=>'#FF3B3B','HIGH'=>'#FFB700','WARNING'=>'#FFB700','INFO'=>'#17D4BE','LOW'=>'#4A9EFF'][strtoupper($sev)] ?? '#7BA3CC';
}
function sevBadge($sev) {
    if (!$sev) return '';
    $s = strtoupper($sev);
    $c = getSevColor($s);
    return "<span class='sev' style='color:$c; border:1px solid $c; box-shadow:0 0 8px {$c}44;'>$s</span>";
}
function getCatIcon($cat) {
    $m = ['SSH'=>'⌨️','SQLi'=>'🛢️','XSS'=>'&lt;/&gt;','RCE'=>'💀','SSTI'=>'{}','LFI'=>'📂'];
    return $m[$cat] ?? '🛡️';
}

$tokens = [];
foreach ($logs as $i => $log) {
    $t = bin2hex(random_bytes(8));
    $_SESSION['terminal_tokens'][$t] = ['ip' => $log['source_ip'], 'log_id' => $log['id'] ?? 0, 'expires' => time() + 300];
    $tokens[$i] = $t;
}
foreach ($_SESSION['terminal_tokens'] ?? [] as $k => $v) { if ($v['expires'] < time()) unset($_SESSION['terminal_tokens'][$k]); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatPulse — SOC Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@600;700&family=IBM+Plex+Sans:wght@400;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<style>
* { box-sizing:border-box; margin:0; padding:0; }
body { 
    background:#020B18; 
    color:#E0EEFF; 
    font-family:'IBM Plex Sans', sans-serif;
    min-height:100vh;
}
body::before {
    content:""; position:fixed; top:0; left:0; width:100vw; height:100vh;
    background:repeating-linear-gradient(0deg,rgba(0,0,0,0.15),rgba(0,0,0,0.15) 1px,transparent 1px,transparent 2px);
    opacity:0.2; pointer-events:none; z-index:9999;
}
.header {
    background:#050F1F;
    border-bottom:2px solid #0D6EFD;
    padding:12px 24px;
    display:flex; justify-content:space-between; align-items:center;
    position:relative;
    box-shadow: 0 0 20px rgba(13,110,253,0.3);
}
.header::after {
    content:''; position:absolute; bottom:-2px; left:0; width:100px; height:2px;
    background:#00B4D8; box-shadow:0 0 10px #00B4D8;
    animation: scanner 3s linear infinite;
}
@keyframes scanner { 0% { left:0%; } 50% { left:90%; } 100% { left:0%; } }
.logo { font-size:1.5rem; font-weight:700; color:#E0EEFF; letter-spacing:3px; font-family:'Rajdhani',sans-serif; text-shadow:0 0 10px #0D6EFD; }
.status-bar { display:flex; align-items:center; gap:12px; font-size:0.8rem; color:#7BA3CC; margin-left:20px; font-family:'Share Tech Mono',monospace; }
.status-dot { width:8px; height:8px; border-radius:50%; background:#17D4BE; box-shadow:0 0 10px #17D4BE; animation:blink 1s infinite; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.2} }
.metrics-grid { display:grid; grid-template-columns:repeat(4,1fr); border-bottom:1px solid rgba(13,110,253,0.15); }
.metric-card {
    padding:20px 24px; text-align:center; border-right:1px solid rgba(13,110,253,0.15);
    background:#0A1628; transition:all 0.3s;
}
.metric-card:last-child { border-right:none; }
.metric-card:hover { transform:scale(1.02); box-shadow:0 0 20px rgba(0,180,216,0.15); z-index:10; }
.metric-label { font-size:0.75rem; letter-spacing:2px; color:#7BA3CC; text-transform:uppercase; margin-bottom:10px; font-family:'IBM Plex Sans',sans-serif; }
.metric-number { font-size:3rem; font-weight:700; font-family:'Rajdhani',sans-serif; text-shadow:0 0 15px currentColor; }
@keyframes pulse { 0% { opacity:0.8; } 50% { opacity:1; } 100% { opacity:0.8; } }
.pulse-num { animation: pulse 2s infinite; }
.text-red { color:#FF3B3B; } .text-cyan { color:#00B4D8; } .text-blue { color:#0D6EFD; }
.filter-bar { background:#050F1F; padding:12px 24px; border-bottom:1px solid rgba(13,110,253,0.15); display:flex; gap:10px; align-items:center; }
.filter-select, .filter-input { background:#020B18; color:#E0EEFF; border:1px solid rgba(13,110,253,0.3); padding:8px 14px; border-radius:4px; font-family:'Share Tech Mono',monospace; font-size:0.8rem; }
.filter-select:focus, .filter-input:focus { outline:none; border-color:#00B4D8; box-shadow:0 0 8px rgba(0,180,216,0.3); }
.filter-btn { background:#0D6EFD; color:#fff; border:none; padding:8px 20px; border-radius:4px; font-weight:600; cursor:pointer; font-size:0.8rem; font-family:'IBM Plex Sans',sans-serif; transition:all 0.2s; }
.filter-btn:hover { background:#00B4D8; box-shadow:0 0 15px rgba(0,180,216,0.4); }
.main-grid { display:grid; grid-template-columns:1fr 380px; height: 450px; }
.panel { border-right:1px solid rgba(13,110,253,0.15); border-bottom:1px solid rgba(13,110,253,0.15); background:#020B18; position:relative; }
.panel-title { padding:10px 16px; font-size:0.75rem; letter-spacing:2px; color:#7BA3CC; text-transform:uppercase; background:#050F1F; border-bottom:1px solid rgba(13,110,253,0.15); font-family:'Rajdhani',sans-serif; font-weight:600; }
.table-scroll { overflow-y:auto; height:320px; transition:height 0.4s cubic-bezier(0.4,0,0.2,1); }
.table-scroll.expanded { height:700px; }
.toggle-btn { display:inline-flex; align-items:center; gap:5px; background:transparent; border:1px solid rgba(0,180,216,0.4); color:#00B4D8; padding:3px 12px; border-radius:20px; font-size:0.68rem; font-family:'Share Tech Mono',monospace; cursor:pointer; letter-spacing:1px; transition:all 0.2s; white-space:nowrap; }
.toggle-btn:hover { background:rgba(0,180,216,0.1); border-color:#00B4D8; box-shadow:0 0 10px rgba(0,180,216,0.3); }
.toggle-btn svg { transition:transform 0.4s; }
.toggle-btn.expanded svg { transform:rotate(180deg); }
.sev-breakdown { display:grid; grid-template-columns:repeat(5,1fr); border-top:1px solid rgba(13,110,253,0.15); background:#050F1F; }
.sev-cell { padding:10px 8px; text-align:center; border-right:1px solid rgba(13,110,253,0.1); }
.sev-cell:last-child { border-right:none; }
.sev-cell-label { font-size:0.62rem; letter-spacing:1px; color:#7BA3CC; text-transform:uppercase; margin-bottom:5px; font-family:'IBM Plex Sans',sans-serif; }
.sev-cell-count { font-size:1.4rem; font-weight:700; font-family:'Rajdhani',sans-serif; text-shadow:0 0 10px currentColor; }
.table-scroll::-webkit-scrollbar { width:6px; }
.table-scroll::-webkit-scrollbar-track { background:#020B18; }
.table-scroll::-webkit-scrollbar-thumb { background:#0D6EFD; border-radius:3px; }
.alerts-tbl { width:100%; border-collapse:collapse; font-family:'Share Tech Mono',monospace; }
.alerts-tbl th { position:sticky; top:0; background:#050F1F; color:#7BA3CC; font-size:0.75rem; letter-spacing:1px; padding:10px 14px; text-align:left; border-bottom:1px solid rgba(13,110,253,0.3); font-family:'IBM Plex Sans',sans-serif; }
.alerts-tbl tr { cursor:pointer; transition:all 0.2s; border-bottom:1px solid rgba(13,110,253,0.05); position:relative; }
.alerts-tbl tr:nth-child(even) { background:#050F1F; }
.alerts-tbl tr:nth-child(odd) { background:#020B18; }
.alerts-tbl td { padding:10px 14px; font-size:0.8rem; }
.alerts-tbl tr:hover { background:rgba(13,110,253,0.1); }
@keyframes flashNew { 0% { background:rgba(23,212,190,0.5); } 100% { background:transparent; } }
.row-new { animation: flashNew 1.5s ease-out; }
.td-time { color:#7BA3CC; white-space:nowrap; }
.td-msg { color:#C0D8F0; max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.sev { display:inline-block; padding:3px 10px; border-radius:12px; font-size:0.7rem; font-weight:700; white-space:nowrap; background:rgba(0,0,0,0.4); text-shadow:0 0 5px currentColor; font-family:'IBM Plex Sans',sans-serif; }
.cat-badge { font-family:'IBM Plex Sans',sans-serif; color:#7BA3CC; font-weight:600; font-size:0.8rem; display:flex; align-items:center; gap:5px; }
.right-col { display:flex; flex-direction:column; background:#050F1F; height:100%; overflow-y:auto; }
.right-panel { padding:16px; border-bottom:1px solid rgba(13,110,253,0.15); background:#0a1628; border-right:none; }
.section-label { font-size:0.7rem; letter-spacing:1px; color:#7BA3CC; margin-bottom:12px; display:flex; justify-content:space-between; font-family:'IBM Plex Sans',sans-serif; font-weight:600; }
.bar-row { margin-bottom:12px; }
.bar-top { display:flex; justify-content:space-between; margin-bottom:5px; font-size:0.8rem; }
.bar-info { display:flex; align-items:center; gap:8px; }
.bar-ip { color:#E0EEFF; font-family:'Share Tech Mono',monospace; cursor:pointer; transition:color 0.2s; }
.bar-ip:hover { color:#00B4D8; text-shadow:0 0 8px #00B4D8; }
.bar-cnt { font-weight:700; font-family:'Rajdhani',sans-serif; color:#E0EEFF; font-size:0.9rem; }
.bar-bg { background:rgba(13,110,253,0.1); border-radius:4px; height:6px; overflow:hidden; box-shadow:inset 0 1px 3px rgba(0,0,0,0.5); }
.bar-fill { height:100%; border-radius:4px; transition:width 1.5s cubic-bezier(0.1, 0.8, 0.2, 1); width:0; }
.rank { font-size:0.75rem; font-weight:700; min-width:24px; font-family:'Rajdhani',sans-serif; }
.chart-wrap { padding:16px 24px 20px; }
/* Tooltip */
.row-tooltip { position:absolute; left:50%; bottom:100%; transform:translateX(-50%) translateY(10px); background:#050F1F; border:1px solid #00B4D8; padding:10px; border-radius:4px; box-shadow:0 0 15px rgba(0,180,216,0.3); color:#E0EEFF; font-family:'Share Tech Mono',monospace; font-size:0.75rem; z-index:100; opacity:0; pointer-events:none; transition:all 0.2s; white-space:normal; width:300px; display:none; }
.alerts-tbl tr:hover .row-tooltip { opacity:1; transform:translateX(-50%) translateY(0); display:block; }
/* Footer */
.footer { padding:12px 24px; background:#020B18; border-top:1px solid rgba(13,110,253,0.15); display:flex; justify-content:space-between; align-items:center; font-family:'IBM Plex Sans',sans-serif; font-size:0.75rem; color:#7BA3CC; }
.kb-shortcuts span { display:inline-block; margin-left:15px; }
.key { background:#0A1628; border:1px solid rgba(13,110,253,0.4); padding:2px 6px; border-radius:3px; color:#E0EEFF; font-family:'Share Tech Mono',monospace; margin-right:4px; }
.world-map { width:100%; height:80px; background-image:radial-gradient(#0D6EFD 1px, transparent 1px); background-size:10px 10px; opacity:0.3; margin-bottom:10px; position:relative; }
.glowing-dot { position:absolute; width:4px; height:4px; background:#00B4D8; border-radius:50%; box-shadow:0 0 8px 2px rgba(0,180,216,0.8); animation:pulse 2s infinite; }

@keyframes mapPulse {
    0%   { r: 4;  opacity: 0.6; }
    70%  { r: 16; opacity: 0;   }
    100% { r: 16; opacity: 0;   }
}
.map-dot:hover circle:last-child {
    filter: brightness(1.4);
    r: 6px;
}
.country-pill:hover {
    border-color: #0D6EFD !important;
    background: rgba(13,110,253,0.1) !important;
}
.country-pill.active {
    border-color: #00B4D8 !important;
    background: rgba(0,180,216,0.1) !important;
}
</style>
</head>
<body>

<header class="header">
    <div style="display:flex; align-items:center;">
        <span class="logo">ThreatPulse</span>
        <div class="status-bar">
            <span class="status-dot"></span>
            <span>SYSTEM STATUS: <strong style="color:#17D4BE;">MONITORING ACTIVE</strong></span>
            <svg width="60" height="20" viewBox="0 0 60 20" style="margin-left:10px;">
                <path d="M0 10 L15 10 L20 2 L25 18 L30 10 L60 10" fill="none" stroke="#17D4BE" stroke-width="1.5">
                    <animate attributeName="stroke-dasharray" values="0,200;200,0" dur="2s" repeatCount="indefinite"/>
                </path>
            </svg>
        </div>
    </div>
    <div style="display:flex; align-items:center;">
        <span style="color:#7BA3CC; font-size:0.85rem; margin-right:20px; font-family:'Share Tech Mono',monospace;">Last updated: <span id="statusTime" style="color:#00B4D8;"></span></span>
        <span style="color:#E0EEFF; font-size:0.85rem; margin-right:20px; font-family:'IBM Plex Sans',sans-serif;">Welcome, <?= htmlspecialchars($_SESSION['analyst']) ?></span>
        <a href="logout.php" style="color:#FF3B3B; text-decoration:none; font-size:0.8rem; font-weight:700; border:1px solid rgba(255,59,59,0.3); padding:6px 14px; border-radius:4px; transition:all 0.2s;">SIGN OUT</a>
    </div>
</header>

<div class="metrics-grid">
    <div class="metric-card">
        <div class="metric-label">ALERTS</div>
        <div class="metric-number text-red pulse-num" data-target="<?= $alertCount ?>">0</div>
    </div>
    <div class="metric-card" style="display:flex; flex-direction:column; align-items:center; position:relative; padding-top:10px;">
        <div class="metric-label">THREAT LEVEL (0-15)</div>
        <canvas id="gaugeCanvas" width="220" height="130"></canvas>
        <div class="gauge-value" id="gaugeNumber"
             style="text-align:center; margin-top:-35px;
                    font-size:2rem; font-weight:700;
                    color:#00B4D8;">
            <?= (int)$threatLevel ?>
        </div>
    </div>
    <div class="metric-card">
        <div class="metric-label">UNIQUE ATTACKERS</div>
        <div class="metric-number text-red pulse-num" data-target="<?= $attackerCount ?>">0</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">EVENTS (TOTAL)</div>
        <div class="metric-number text-blue pulse-num" data-target="<?= $eventCount ?>">0</div>
    </div>
</div>

<div class="filter-bar">
    <form method="POST" action="dashboard.php" id="filterForm" style="display:flex; gap:10px; align-items:center; width:100%; margin:0;">
        <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        <input type="hidden" name="filter_submit" value="1">
        <select name="time" class="filter-select">
            <option value="all" <?= $f_time==='all'?'selected':'' ?>>All Time</option>
            <option value="today" <?= $f_time==='today'?'selected':'' ?>>Today</option>
            <option value="week" <?= $f_time==='week'?'selected':'' ?>>This Week</option>
            <option value="month" <?= $f_time==='month'?'selected':'' ?>>This Month</option>
        </select>
        <select name="sort" class="filter-select">
            <option value="time_desc" <?= $f_sort==='time_desc'?'selected':'' ?>>Newest First</option>
            <option value="time_asc" <?= $f_sort==='time_asc'?'selected':'' ?>>Oldest First</option>
            <option value="severity_desc" <?= $f_sort==='severity_desc'?'selected':'' ?>>Severity ↓</option>
            <option value="severity_asc" <?= $f_sort==='severity_asc'?'selected':'' ?>>Severity ↑</option>
        </select>
        <select name="cat" class="filter-select">
            <option value="" <?= $f_cat===''?'selected':'' ?>>All Categories</option>
            <?php foreach(['SSH','SQLi','XSS','RCE','SSTI','LFI','Other'] as $c): ?>
            <option value="<?= $c ?>" <?= $f_cat===$c?'selected':'' ?>><?= $c ?></option>
            <?php endforeach; ?>
        </select>
        <input type="text" name="ip" placeholder="Filter by IP..." class="filter-input" style="width:160px;" value="<?= htmlspecialchars($f_ip) ?>">
        <button type="submit" class="filter-btn" id="btnFilter">Apply</button>
        <?php if ($f_cat || $f_ip || $f_time !== 'all'): ?>
        <button type="button" onclick="window.location='dashboard.php?clear=1'" class="filter-btn" style="background:transparent; border:1px solid #FF3B3B; color:#FF3B3B;" id="btnReset">✕ Clear</button>
        <?php endif; ?>
    </form>
</div>

<div class="main-grid">
    <div class="panel" style="display:flex; flex-direction:column; border-bottom:0;">
        <div class="panel-title" style="display:flex; justify-content:space-between; align-items:center;">
            <span>ALERTS &mdash; DETAILS</span>
            <div style="display:flex; align-items:center; gap:12px;">
                <span style="font-size:0.7rem; color:#00B4D8; font-family:'Share Tech Mono',monospace;"><?= count($logs) ?> events</span>
                <button class="toggle-btn" id="alertToggleBtn" onclick="toggleAlertTable()">
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                        <path d="M1 3L5 7L9 3" stroke="#00B4D8" stroke-width="1.5" stroke-linecap="round"/>
                    </svg>
                    <span id="alertToggleLabel">VIEW ALL</span>
                </button>
            </div>
        </div>
        <div class="table-scroll" id="alertTableScroll">
            <table class="alerts-tbl">
                <thead><tr><th>TIME</th><th>SEVERITY</th><th>CATEGORY</th><th>MESSAGE</th></tr></thead>
                <tbody>
                <?php foreach ($logs as $i => $log): 
                    $tok = htmlspecialchars($tokens[$i]);
                    $ts = $log['timestamp']; $time = is_numeric($ts) ? date('M d H:i:s', $ts) : date('M d H:i:s', strtotime($ts));
                    $scolor = getSevColor($log['severity']);
                ?>
                <tr class="log-row <?= $i<3 ? 'row-new' : '' ?>" data-token="<?= $tok ?>" style="border-left:3px solid transparent;" onmouseover="this.style.borderLeftColor='<?= $scolor ?>'" onmouseout="this.style.borderLeftColor='transparent'">
                    <td class="td-time"><?= htmlspecialchars($time) ?></td>
                    <td><?= sevBadge($log['severity']) ?></td>
                    <td><span class="cat-badge"><?= getCatIcon($log['category']) ?> <?= htmlspecialchars($log['category']) ?></span></td>
                    <td class="td-msg">
                        <?= htmlspecialchars($log['message']) ?>
                        <div class="row-tooltip">
                            <strong style="color:<?= $scolor ?>"><?= htmlspecialchars($log['severity']) ?> ALERT</strong><br><br>
                            IP: <?= htmlspecialchars($log['source_ip']) ?><br>
                            Cat: <?= htmlspecialchars($log['category']) ?><br>
                            Time: <?= htmlspecialchars($time) ?><br><br>
                            Msg: <?= htmlspecialchars($log['message']) ?>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <?php
        // Severity breakdown counts
        $sevBreak = ['CRITICAL'=>0,'HIGH'=>0,'WARNING'=>0,'INFO'=>0,'LOW'=>0];
        foreach ($logs as $l) {
            $s = strtoupper($l['severity'] ?? '');
            if (isset($sevBreak[$s])) $sevBreak[$s]++;
        }
        $sevColors = ['CRITICAL'=>'#FF3B3B','HIGH'=>'#FFB700','WARNING'=>'#FF8C00','INFO'=>'#17D4BE','LOW'=>'#4A9EFF'];
        ?>
        <div class="sev-breakdown">
            <?php foreach ($sevBreak as $label => $count): ?>
            <div class="sev-cell">
                <div class="sev-cell-label"><?= $label ?></div>
                <div class="sev-cell-count" style="color:<?= $sevColors[$label] ?>"><?= number_format($count) ?></div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>

    <div class="right-col">
<div class="panel" style="border-right:none;">
    <div class="panel-title">
        🌍 THREAT ORIGIN — TOP COUNTRIES
    </div>

    <!-- Header row -->
    <div style="display:grid;
                grid-template-columns:1fr auto auto;
                gap:8px;
                padding:8px 16px;
                font-size:0.68rem;
                color:#7BA3CC;
                letter-spacing:1px;
                text-transform:uppercase;
                border-bottom:1px solid rgba(13,110,253,0.1);">
        <span>Country</span>
        <span style="text-align:right;">IPs</span>
        <span style="text-align:right;">Alerts</span>
    </div>

    <?php 
    $displayData = empty($countryStats) 
                 ? $ipFallback 
                 : $countryStats;
    foreach ($displayData as $i => $row):
        $pct  = round(($row['alert_count']/$maxStat)*100);
        $flag = $flags[$row['country_code']] ?? '🌐';
        $name = $useIPFallback 
              ? $row['source_ip'] 
              : ($row['country_name'] ?? 'Unknown');
        // Color based on rank
        $colors = [
            '#FF3B3B','#FF6B35','#FFB700',
            '#F39C12','#0D6EFD','#00B4D8',
        ];
        $barColor = $colors[min($i, count($colors)-1)];
    ?>
    <div style="padding:8px 16px;
                border-bottom:1px solid rgba(13,110,253,0.05);
                transition:background 0.15s;"
         onmouseenter="this.style.background='rgba(13,110,253,0.08)'"
         onmouseleave="this.style.background=''">

        <!-- Country name + flag -->
        <div style="display:grid;
                    grid-template-columns:1fr auto auto;
                    gap:8px;
                    align-items:center;
                    margin-bottom:5px;">
            <span style="display:flex;
                         align-items:center;
                         gap:6px;
                         overflow:hidden;">
                <span style="font-size:1rem;
                             flex-shrink:0;">
                    <?= $flag ?>
                </span>
                <span style="color:#E0EEFF;
                             font-size:0.8rem;
                             font-family:monospace;
                             overflow:hidden;
                             text-overflow:ellipsis;
                             white-space:nowrap;">
                    <?= htmlspecialchars($name) ?>
                </span>
            </span>
            <span style="color:#7BA3CC;
                         font-size:0.75rem;
                         text-align:right;
                         white-space:nowrap;">
                <?= number_format($row['ip_count']) ?>
            </span>
            <span style="color:<?= $barColor ?>;
                         font-weight:700;
                         font-size:0.8rem;
                         text-align:right;
                         white-space:nowrap;
                         min-width:36px;">
                <?= number_format($row['alert_count']) ?>
            </span>
        </div>

        <!-- Progress bar -->
        <div style="background:rgba(255,255,255,0.05);
                    border-radius:3px;
                    height:4px;
                    overflow:hidden;">
            <div style="width:<?= $pct ?>%;
                        height:100%;
                        background:<?= $barColor ?>;
                        border-radius:3px;
                        box-shadow:0 0 6px <?= $barColor ?>66;">
            </div>
        </div>
    </div>
    <?php endforeach; ?>

    <!-- Footer total -->
    <?php
    $totalCountries = $pdo->query("
        SELECT COUNT(DISTINCT country_code) 
        FROM ip_geo
    ")->fetchColumn();
    ?>
    <div style="padding:10px 16px;
                font-size:0.72rem;
                color:#4A7A9B;
                text-align:center;
                border-top:1px solid rgba(13,110,253,0.1);">
        Attacks detected from 
        <span style="color:#00B4D8;">
            <?= $totalCountries ?: count($displayData) ?>
        </span> 
        countries worldwide
    </div>
</div>

        <div class="panel right-panel">
            <div class="panel-title" style="margin:-16px -16px 16px -16px;">TOP ATTACKERS</div>
            <div class="section-label"><span>IP ADDRESS</span><span>ALERTS</span></div>
<div style="padding:4px 0;">
<?php foreach ($topAttackers as $i => $a):
    $pct   = round(($a['cnt'] / $maxAttacks) * 100);
    $color = $medals[$i] ?? '#0D6EFD';
    $glow  = $i < 3 
           ? "box-shadow:0 0 8px {$color}66;" 
           : '';
?>
<div style="display:flex; align-items:center;
            gap:10px; padding:7px 16px;
            border-bottom:1px solid rgba(13,110,253,0.06);">

    <!-- Rank -->
    <span style="color:<?= $color ?>;
                 font-weight:700;
                 font-size:0.78rem;
                 font-family:monospace;
                 min-width:28px;
                 text-align:right;">
        #<?= $i + 1 ?>
    </span>

    <!-- IP + Bar -->
    <div style="flex:1; min-width:0;">
        <div style="display:flex;
                    justify-content:space-between;
                    align-items:center;
                    margin-bottom:5px;">
            <span style="color:#E0EEFF;
                         font-size:0.8rem;
                         font-family:'Share Tech Mono',monospace;
                         overflow:hidden;
                         text-overflow:ellipsis;
                         white-space:nowrap;
                         max-width:160px;">
                <?= htmlspecialchars($a['source_ip']) ?>
            </span>
            <span style="color:<?= $color ?>;
                         font-weight:700;
                         font-size:0.82rem;
                         margin-left:8px;
                         white-space:nowrap;">
                <?= number_format($a['cnt']) ?>
            </span>
        </div>

        <!-- Bar track -->
        <div style="background:rgba(255,255,255,0.06);
                    border-radius:4px;
                    height:10px;
                    overflow:hidden;">
            <!-- Bar fill -->
            <div style="width:<?= $pct ?>%;
                        height:100%;
                        background:linear-gradient(
                            90deg,
                            <?= $color ?>,
                            <?= $i<3 ? '#00B4D8' : '#0D6EFD' ?>
                        );
                        border-radius:4px;
                        <?= $glow ?>
                        transition:width 1.2s ease;">
            </div>
        </div>
    </div>
</div>
<?php endforeach; ?>
</div>
        </div>

        <div class="panel right-panel" style="flex:1;">
            <div class="panel-title" style="margin:-16px -16px 16px -16px;">ALERTS BY CATEGORY</div>
            <div class="section-label"><span>CATEGORY</span><span>EVENTS</span></div>
            <?php foreach ($catStats as $cat): $pct = round(($cat['cnt']/$maxCat)*100); ?>
            <div class="bar-row">
                <div class="bar-top">
                    <span class="bar-ip"><span style="margin-right:6px;"><?= getCatIcon($cat['category']) ?></span><?= htmlspecialchars($cat['category']) ?></span>
                    <span class="bar-cnt" style="color:#00B4D8;"><?= $cat['cnt'] ?></span>
                </div>
                <div class="bar-bg"><div class="bar-fill" style="background:linear-gradient(90deg,#0D6EFD,#00B4D8); box-shadow:0 0 10px rgba(0,180,216,0.5);" data-width="<?= $pct ?>%"></div></div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<div style="border-top:1px solid rgba(13,110,253,0.15); background:#020B18;">

    <!-- Map Header -->
    <div style="background:#050F1F;
                padding:8px 20px;
                border-bottom:1px solid rgba(13,110,253,0.15);
                display:flex;
                justify-content:space-between;
                align-items:center;
                font-family:'Rajdhani',sans-serif;
                font-weight:600;">
        <span style="font-size:0.68rem;letter-spacing:2px;
                     color:#7BA3CC;text-transform:uppercase;">
            🌍 Threat Origin — Global Attack Map
        </span>
        <div style="display:flex;align-items:center;gap:16px;">
            <span style="font-size:0.72rem;color:#00B4D8;
                         font-family:'Share Tech Mono',monospace;"
                  id="mapFilterLabel"></span>
            <button id="mapResetBtn"
                    style="display:none;background:transparent;
                           border:1px solid #FF3B3B44;color:#FF3B3B;
                           padding:3px 10px;border-radius:4px;
                           font-size:0.72rem;cursor:pointer;
                           font-family:'Share Tech Mono',monospace;"
                    onclick="resetMapFilter()">
                ✕ Clear Filter
            </button>
            <span style="font-size:0.72rem;color:#4A7A9B;
                         font-family:'Share Tech Mono',monospace;">
                <?= count($mapDots) ?> sources mapped
            </span>
        </div>
    </div>

    <!-- SVG World Map -->
    <div style="background:#020B18;position:relative;
                overflow:hidden;height:300px;" id="mapWrap">

        <!-- Leaflet Cartographic World Map -->
        <div id="map" style="width: 100%; height: 100%; z-index: 1;"></div>
        
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            const mapDots = <?= json_encode($mapDots, JSON_NUMERIC_CHECK) ?>;
            const maxAlerts = <?= $mapMaxAlerts ?: 1 ?>;

            const map = L.map('map', {
                center: [20, 0],
                zoom: 2,
                worldCopyJump: true,
                minZoom: 2,
                maxBounds: [[-90, -180], [90, 180]]
            });

            // CartoDB Dark Matter base map
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; CartoDB',
                subdomains: 'abcd',
                maxZoom: 19
            }).addTo(map);

            // Add attack origin dots
            mapDots.forEach(dot => {
                let lat = dot.latitude;
                let lng = dot.longitude;
                if(!lat || !lng) return;

                let ratio = Math.log(dot.alert_count + 1) / Math.log(maxAlerts + 1);
                let radius = 3 + (ratio * 10);
                
                let color = '#FF3B3B';

                let circle = L.circleMarker([lat, lng], {
                    radius: radius,
                    fillColor: color,
                    color: color,
                    weight: ratio > 0.3 ? 2 : 1,
                    opacity: 0.8,
                    fillOpacity: ratio > 0.3 ? 0.6 : 0.3,
                    className: ratio > 0.3 ? 'leaflet-glowing-marker' : ''
                }).addTo(map);
                
                // Tooltip
                let tooltipHtml = `
                    <div style="font-family:'Share Tech Mono', monospace; font-size:13px; color:#E0EEFF; min-width:120px; line-height:1.4;">
                        <span style="color:${color}; font-weight:bold; font-size:14px;">${dot.source_ip}</span><br/>
                        ${dot.city ? dot.city+', ' : ''}${dot.country_name || dot.country_code}<br/>
                        <div style="margin-top:4px; border-top:1px solid rgba(255,255,255,0.1); padding-top:4px;">
                            <span style="color:#7BA3CC">ALERTS:</span> ${dot.alert_count}
                        </div>
                    </div>
                `;
                circle.bindTooltip(tooltipHtml, {
                    direction: 'top',
                    className: 'leaflet-dark-tooltip',
                    offset: [0, -radius]
                });
            });
            
            // Fix map size explicitly when parent container sizes
            setTimeout(() => map.invalidateSize(), 500);
        });
        </script>
        
        <style>
        /* Map custom overrides */
        .leaflet-container { background: #020B18 !important; }
        .leaflet-tile-pane {
            filter: brightness(0.55) sepia(1) hue-rotate(180deg) saturate(5);
        }
        .leaflet-dark-tooltip {
            background: rgba(5, 15, 31, 0.95) !important;
            border: 1px solid rgba(13, 110, 253, 0.4) !important;
            border-radius: 4px !important;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.8) !important;
        }
        .leaflet-dark-tooltip::before { border-top-color: rgba(13, 110, 253, 0.4) !important; }
        .leaflet-glowing-marker {
            animation: mapMarkerPulse 2s infinite ease-out;
        }
        @keyframes mapMarkerPulse {
            0% { filter: drop-shadow(0 0 2px currentColor); }
            50% { filter: drop-shadow(0 0 10px currentColor); }
            100% { filter: drop-shadow(0 0 2px currentColor); }
        }
        </style>

        <!-- Tooltip -->
        <div id="mapTooltip"
             style="position:absolute;display:none;
                    background:#050F1F;
                    border:1px solid rgba(0,180,216,0.5);
                    border-radius:6px;padding:10px 14px;
                    font-family:'Share Tech Mono',monospace;
                    font-size:0.78rem;color:#E0EEFF;
                    pointer-events:none;z-index:100;
                    min-width:180px;
                    box-shadow:0 4px 20px rgba(0,0,0,0.6);">
        </div>
    </div>

    <!-- Country pills bar -->
    <div style="background:#050F1F;
                padding:8px 20px;
                border-top:1px solid rgba(13,110,253,0.15);
                display:flex;flex-wrap:wrap;gap:6px;
                align-items:center;">

        <?php
        $flagMap = [
            'US'=>'🇺🇸','CN'=>'🇨🇳','RU'=>'🇷🇺',
            'DE'=>'🇩🇪','GB'=>'🇬🇧','FR'=>'🇫🇷',
            'NL'=>'🇳🇱','BR'=>'🇧🇷','IN'=>'🇮🇳',
            'KR'=>'🇰🇷','JP'=>'🇯🇵','SG'=>'🇸🇬',
            'RO'=>'🇷🇴','TH'=>'🇹🇭','TW'=>'🇹🇼',
            'UA'=>'🇺🇦','VN'=>'🇻🇳','ID'=>'🇮🇩',
            'TR'=>'🇹🇷','PK'=>'🇵🇰','HK'=>'🇭🇰',
            'IR'=>'🇮🇷','CA'=>'🇨🇦','AU'=>'🇦🇺',
            'IT'=>'🇮🇹','ES'=>'🇪🇸','PL'=>'🇵🇱',
            'NG'=>'🇳🇬','ZA'=>'🇿🇦','MX'=>'🇲🇽',
        ];
        foreach ($mapCountries as $c):
            $flag = $flagMap[$c['country_code']] ?? '🌐';
            $cc   = htmlspecialchars($c['country_code']);
            $name = htmlspecialchars($c['country_name']);
        ?>
        <div class="country-pill"
             data-code="<?= $cc ?>"
             onclick="filterMapCountry('<?= $cc ?>')"
             style="display:flex;align-items:center;
                    gap:6px;background:#0A1628;
                    border:1px solid rgba(13,110,253,0.2);
                    border-radius:20px;padding:4px 10px;
                    cursor:pointer;transition:all 0.2s;
                    font-family:'Share Tech Mono',monospace;">
            <span style="font-size:16px;"><?= $flag ?></span>
            <span style="color:#E0EEFF;font-size:0.72rem;">
                <?= $name ?>
            </span>
            <span style="background:rgba(255,59,59,0.15);
                         color:#FF3B3B;border-radius:10px;
                         padding:1px 7px;font-size:0.7rem;
                         font-weight:700;">
                <?= number_format($c['alert_count']) ?>
            </span>
        </div>
        <?php endforeach; ?>
    </div>
</div>

<div class="footer">
    <div>ThreatPulse - Advanced Security Operations Center v3.1</div>
    <div class="kb-shortcuts">
        <span><span class="key">F</span> Filter</span>
        <span><span class="key">R</span> Refresh</span>
        <span><span class="key">Esc</span> Clear</span>
    </div>
</div>

<input type="hidden" id="csrfToken" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

<script>
function toggleAlertTable() {
    const scroll = document.getElementById('alertTableScroll');
    const btn    = document.getElementById('alertToggleBtn');
    const label  = document.getElementById('alertToggleLabel');
    const isExp  = scroll.classList.toggle('expanded');
    btn.classList.toggle('expanded', isExp);
    label.textContent = isExp ? 'VIEW LESS' : 'VIEW ALL';
}

function updateClock() {
    const el = document.getElementById('statusTime');
    if (el) {
        let now = new Date();
        el.textContent = now.toLocaleTimeString('en-US', { hour12: false }) + ' LOCAL';
    }
}
setInterval(updateClock, 1000); updateClock();

function fitMapHeight() {
    const wrap   = document.getElementById('mapWrap');
    const footer = document.querySelector('.footer');
    if (!wrap || !footer) return;
    // Distance from mapWrap top to footer top — always accurate regardless of scroll
    const gap = footer.getBoundingClientRect().top - wrap.getBoundingClientRect().top;
    wrap.style.height = Math.max(220, gap) + 'px';
}
fitMapHeight();
window.addEventListener('resize', fitMapHeight);

setTimeout(() => {
    document.querySelectorAll('.metric-number').forEach(el => {
        const target = parseInt(el.dataset.target) || 0;
        let cur = 0; const step = Math.max(1, Math.ceil(target / 40));
        const timer = setInterval(() => {
            cur = Math.min(cur + step, target); el.textContent = cur.toLocaleString();
            if (cur >= target) clearInterval(timer);
        }, 30);
    });
    document.querySelectorAll('.bar-fill').forEach(el => { el.style.width = el.dataset.width; });
}, 100);

function drawGauge(value) {
    const canvas = document.getElementById('gaugeCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = canvas.width  / 2;
    const cy = canvas.height * 0.85;
    const r  = Math.min(cx, cy) * 0.82;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Background arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, Math.PI, 2 * Math.PI);
    ctx.strokeStyle = 'rgba(13,110,253,0.15)';
    ctx.lineWidth = 16;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Color gradient arc (green → amber → red)
    if (value > 0) {
        const pct = value / 15;
        const endAngle = Math.PI + (Math.PI * pct);

        // Pick color based on value
        let color;
        if (value <= 5)       color = '#00FF9C'; // green
        else if (value <= 10) color = '#FFB700'; // amber
        else                  color = '#FF3B3B'; // red

        ctx.beginPath();
        ctx.arc(cx, cy, r, Math.PI, endAngle);
        ctx.strokeStyle = color;
        ctx.lineWidth = 16;
        ctx.lineCap = 'round';
        ctx.stroke();

        // Glow effect
        ctx.beginPath();
        ctx.arc(cx, cy, r, Math.PI, endAngle);
        ctx.strokeStyle = color;
        ctx.lineWidth = 28;
        ctx.globalAlpha = 0.15;
        ctx.stroke();
        ctx.globalAlpha = 1.0;
    }
}

// Pass real PHP value to JS
const THREAT_LEVEL = <?= (int)$threatLevel ?>;

// Draw on load
document.addEventListener('DOMContentLoaded', () => {
    drawGauge(THREAT_LEVEL);
    // Update gauge number display
    const gaugeNum = document.querySelector('.gauge-value, #gaugeNumber');
    if (gaugeNum) gaugeNum.textContent = THREAT_LEVEL;
});

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.log-row').forEach(row => {
        row.addEventListener('click', function() {
            const token = this.dataset.token; if (!token) return;
            const form = document.createElement('form'); form.method = 'POST'; form.action = 'terminal.php';
            const t = document.createElement('input'); t.type = 'hidden'; t.name = 'token'; t.value = token;
            const c = document.createElement('input'); c.type = 'hidden'; c.name = 'csrf_token'; c.value = document.getElementById('csrfToken')?.value || '';
            form.appendChild(t); form.appendChild(c); document.body.appendChild(form); form.submit();
        });
    });

    document.addEventListener('keydown', e => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
        if (e.key === 'f' || e.key === 'F') { e.preventDefault(); document.querySelector('input[name="ip"]').focus(); }
        if (e.key === 'r' || e.key === 'R') { window.location.reload(); }
        if (e.key === 'Escape') { window.location = 'dashboard.php?clear=1'; }
    });
});

// Map tooltip
function showMapTooltip(e, ip, city, country, alerts) {
    const tip = document.getElementById('mapTooltip');
    const wrap = document.getElementById('mapWrap');
    if (!tip || !wrap) return;
    
    const wRect = wrap.getBoundingClientRect();
    let x = e.clientX - wRect.left + 12;
    let y = e.clientY - wRect.top  - 10;
    if (x + 200 > wRect.width)  x -= 220;
    if (y + 100 > wRect.height) y -= 110;
    
    tip.style.left    = x + 'px';
    tip.style.top     = y + 'px';
    tip.style.display = 'block';
    tip.innerHTML = `
        <div style="color:#00B4D8;font-weight:700;
                    margin-bottom:4px;">${ip}</div>
        <div style="color:#7BA3CC;font-size:0.72rem;
                    margin-bottom:4px;">
            ${city ? city + ', ' : ''}${country}
        </div>
        <div style="color:#FF3B3B;font-weight:700;">
            ${alerts.toLocaleString()} alerts
        </div>
        <div style="color:#4A7A9B;font-size:0.68rem;
                    margin-top:6px;">
            Click to filter dashboard
        </div>
    `;
}
function hideMapTooltip() {
    const tip = document.getElementById('mapTooltip');
    if (tip) tip.style.display = 'none';
}

// Filter dashboard by country
let activeMapCountry = null;
function filterMapCountry(countryCode) {
    if (activeMapCountry === countryCode) {
        resetMapFilter(); return;
    }
    activeMapCountry = countryCode;

    // Dim non-matching dots
    document.querySelectorAll('.map-dot').forEach(d => {
        d.style.opacity = 
            d.dataset.country === countryCode ? '1' : '0.1';
    });

    // Highlight pill
    document.querySelectorAll('.country-pill').forEach(p => {
        p.classList.toggle('active', 
            p.dataset.code === countryCode);
    });

    // Show reset button
    const btn = document.getElementById('mapResetBtn');
    const lbl = document.getElementById('mapFilterLabel');
    if (btn) btn.style.display = 'inline-block';
    if (lbl) lbl.textContent = 'FILTERED: ' + countryCode;

    // Filter alerts table rows
    document.querySelectorAll('.log-row').forEach(row => {
        // Simple filter visually
    });
}
function resetMapFilter() {
    activeMapCountry = null;
    document.querySelectorAll('.map-dot').forEach(d => {
        d.style.opacity = '1';
    });
    document.querySelectorAll('.country-pill').forEach(p => {
        p.classList.remove('active');
    });
    const btn = document.getElementById('mapResetBtn');
    const lbl = document.getElementById('mapFilterLabel');
    if (btn) btn.style.display = 'none';
    if (lbl) lbl.textContent = '';
}
</script>
<script>
// Real-time polling system
(function() {
    let lastChecked = new Date().toISOString()
        .slice(0,19).replace('T',' ');
    let pollInterval = null;
    let isPolling = false;

    // Live indicator in header
    const liveIndicator = document.createElement('span');
    liveIndicator.id = 'liveIndicator';
    liveIndicator.style.cssText = `
        display:inline-flex; align-items:center;
        gap:5px; font-size:0.72rem; color:#4A7A9B;
        font-family:'Share Tech Mono',monospace;
        margin-left:16px;
    `;
    liveIndicator.innerHTML = 
        '<span id="liveDot" style="width:7px;height:7px;'
        + 'border-radius:50%;background:#4A7A9B;'
        + 'display:inline-block;"></span>'
        + '<span id="liveText">LIVE</span>';
    
    // Attach to status bar
    const statusBar = document.querySelector('.status-bar');
    if (statusBar) statusBar.appendChild(liveIndicator);

    function setLiveStatus(state) {
        const dot  = document.getElementById('liveDot');
        const text = document.getElementById('liveText');
        if (!dot || !text) return;
        
        const states = {
            active:  { color:'#00FF9C', label:'LIVE' },
            fetching:{ color:'#FFB700', label:'UPDATING...' },
            error:   { color:'#FF3B3B', label:'RETRY' },
            offline: { color:'#4A7A9B', label:'PAUSED' },
        };
        const s = states[state] || states.offline;
        dot.style.background  = s.color;
        dot.style.boxShadow   = `0 0 6px ${s.color}`;
        text.textContent = s.label;
        text.style.color = s.color;
    }

    // Toast notification for new alerts
    function showToast(count, topEntry) {
        const existing = document.getElementById('liveToast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.id = 'liveToast';
        toast.style.cssText = `
            position:fixed; bottom:24px; right:24px;
            background:#050F1F;
            border:1px solid rgba(0,180,216,0.5);
            border-left:3px solid #00B4D8;
            border-radius:6px; padding:12px 16px;
            font-family:'Share Tech Mono',monospace;
            font-size:0.78rem; color:#E0EEFF;
            z-index:9999; max-width:320px;
            box-shadow:0 4px 20px rgba(0,0,0,0.6);
            animation:slideIn 0.3s ease;
        `;

        const sev   = topEntry?.severity || 'INFO';
        const sevColors = {
            CRITICAL:'#FF3B3B', HIGH:'#FFB700',
            WARNING:'#FFD700',  INFO:'#00B4D8',
        };
        const col = sevColors[sev] || '#00B4D8';

        toast.innerHTML = `
            <div style="color:#00B4D8;font-weight:700;
                        margin-bottom:6px;">
                +${count} new alert${count>1?'s':''}
            </div>
            ${topEntry ? \`
            <div style="color:${col};font-size:0.72rem;">
                ${topEntry.severity} · ${topEntry.category}
            </div>
            <div style="color:#7BA3CC;font-size:0.7rem;
                        margin-top:4px;overflow:hidden;
                        text-overflow:ellipsis;
                        white-space:nowrap;max-width:280px;">
                ${topEntry.message?.slice(0,60)}...
            </div>\` : ''}
            <div style="color:#4A7A9B;font-size:0.68rem;
                        margin-top:8px;">
                Click to refresh dashboard
            </div>
        `;

        toast.style.cursor = 'pointer';
        toast.addEventListener('click', () => {
            window.location.reload();
        });

        document.body.appendChild(toast);

        // Add slide-in animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform:translateX(120%); opacity:0; }
                to   { transform:translateX(0);    opacity:1; }
            }
        `;
        document.head.appendChild(style);

        // Auto-dismiss after 8 seconds
        setTimeout(() => {
            toast.style.transition = 'opacity 0.5s';
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 500);
        }, 8000);
    }

    // Update metric cards without reload
    function updateMetrics(totals) {
        const alertEl = document.querySelector(
            '.metric-number.text-red[data-target]'
        );
        const attackerEl = document.querySelectorAll(
            '.metric-number.text-red[data-target]'
        )[1];
        const eventEl = document.querySelector(
            '.metric-number.text-blue[data-target]'
        );

        if (alertEl && totals.total) {
            alertEl.textContent = 
                parseInt(totals.total).toLocaleString();
            alertEl.dataset.target = totals.total;
        }
        if (attackerEl && totals.attackers) {
            attackerEl.textContent = 
                parseInt(totals.attackers).toLocaleString();
        }
        if (eventEl && totals.total) {
            eventEl.textContent = 
                parseInt(totals.total).toLocaleString();
        }
    }

    // Main poll function
    async function poll() {
        if (isPolling) return;
        isPolling = true;
        setLiveStatus('fetching');

        try {
            const url = \`live_status.php?since=\${
                encodeURIComponent(lastChecked)
            }\`;
            const resp = await fetch(url, {
                credentials: 'same-origin',
                cache: 'no-store',
            });

            if (!resp.ok) throw new Error(resp.status);

            const data = await resp.json();

            // Update last checked time
            lastChecked = data.server_time;

            // Update header timestamp
            const timeEl = document.querySelector('#statusTime');
                timeEl.textContent = 'UPDATED...';

            // If new alerts came in
            if (data.new_count > 0) {
                showToast(data.new_count, data.latest[0]);
                updateMetrics(data.totals);
                // Flash the status dot
                setLiveStatus('active');
            } else {
                setLiveStatus('active');
            }

        } catch (err) {
            console.warn('[Live] Poll failed:', err);
            setLiveStatus('error');
        } finally {
            isPolling = false;
        }
    }

    // Start polling every 30 seconds
    function startPolling() {
        setLiveStatus('active');
        poll(); // immediate first check
        pollInterval = setInterval(poll, 30000);
    }

    // Pause when tab is hidden (save resources)
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            clearInterval(pollInterval);
            setLiveStatus('offline');
        } else {
            startPolling();
        }
    });

    // Start on load
    document.addEventListener('DOMContentLoaded', startPolling);
})();
</script>
</body>
</html>
