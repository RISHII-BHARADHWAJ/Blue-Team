<?php
session_name('CYBERTECH_SECURE_SESSION');
session_start(['cookie_httponly'=>true,'cookie_samesite'=>'Strict','use_strict_mode'=>true]);
$_SESSION['analyst']='analyst';
$_SESSION['username']='analyst';
$_SESSION['role']='analyst';
$_SESSION['user_id']=2;

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
$critCount = $pdo->prepare("SELECT COUNT(*) FROM logs WHERE severity='CRITICAL' AND $whereSQL"); $critCount->execute($params); $critTotal = $critCount->fetchColumn();
$threatLevel = $alertCount > 0 ? min(15, round(($critTotal / $alertCount) * 15)) : 0;

$logQuery = $pdo->prepare("SELECT timestamp, severity, category, message, source_ip FROM logs WHERE $whereSQL ORDER BY $orderSQL LIMIT 200");
$logQuery->execute($params);
$logs = $logQuery->fetchAll();

$topAttackers = $pdo->query("SELECT source_ip, COUNT(*) as cnt FROM logs GROUP BY source_ip ORDER BY cnt DESC LIMIT 10")->fetchAll();
$maxAttacks = $topAttackers[0]['cnt'] ?? 1;

$catStats = $pdo->query("SELECT category, COUNT(*) as cnt FROM logs GROUP BY category ORDER BY cnt DESC")->fetchAll();
$maxCat = $catStats[0]['cnt'] ?? 1;

$chartData = $pdo->query("SELECT category, COUNT(*) as cnt FROM logs GROUP BY category ORDER BY cnt DESC LIMIT 8")->fetchAll();

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
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@600;700&family=IBM+Plex+Sans:wght@400;600&display=swap" rel="stylesheet">
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
.main-grid { display:grid; grid-template-columns:1fr 380px; min-height:500px; }
.panel { border-right:1px solid rgba(13,110,253,0.15); border-bottom:1px solid rgba(13,110,253,0.15); background:#020B18; position:relative; }
.panel-title { padding:10px 16px; font-size:0.75rem; letter-spacing:2px; color:#7BA3CC; text-transform:uppercase; background:#050F1F; border-bottom:1px solid rgba(13,110,253,0.15); font-family:'Rajdhani',sans-serif; font-weight:600; }
.table-scroll { overflow-y:auto; max-height:460px; }
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
.right-col { display:flex; flex-direction:column; background:#050F1F; }
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
        <canvas id="gaugeCanvas" width="180" height="90"></canvas>
        <div class="metric-number text-cyan pulse-num" style="position:absolute; bottom:15px;" data-target="<?= $threatLevel ?>">0</div>
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
        <div class="panel-title">ALERTS — DETAILS</div>
        <div class="table-scroll" style="flex:1;">
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
        
        <div style="border-top:1px solid rgba(13,110,253,0.15); background:#050F1F;">
            <div class="panel-title">ATTACK VECTORS</div>
            <div class="chart-wrap"><canvas id="attackChart" height="150"></canvas></div>
        </div>
    </div>

    <div class="right-col">
        <div class="panel right-panel">
            <div class="panel-title" style="margin:-16px -16px 16px -16px;">THREAT ORIGIN MAP</div>
            <div class="world-map">
                <div class="glowing-dot" style="top:20%; left:30%;"></div>
                <div class="glowing-dot" style="top:50%; left:70%; animation-delay:1s;"></div>
                <div class="glowing-dot" style="top:30%; left:80%; animation-delay:0.5s;"></div>
            </div>
            <div class="section-label"><span>IP ADDRESS</span><span>ALERTS</span></div>
            <?php 
            $medals=['#FFD700','#C0C0C0','#CD7F32'];
            foreach ($topAttackers as $i => $a):
                $pct = round(($a['cnt']/$maxAttacks)*100);
                $col = $medals[$i] ?? '#0D6EFD';
            ?>
            <div class="bar-row">
                <div class="bar-top">
                    <div class="bar-info"><span class="rank" style="color:<?= $col ?>">#<?= $i+1 ?></span><span class="bar-ip"><?= htmlspecialchars($a['source_ip']) ?></span></div>
                    <span class="bar-cnt" style="color:<?= $col ?>"><?= $a['cnt'] ?></span>
                </div>
                <div class="bar-bg"><div class="bar-fill" style="background:linear-gradient(90deg,#0D6EFD,#00B4D8); box-shadow:0 0 10px rgba(0,180,216,0.5);" data-width="<?= $pct ?>%"></div></div>
            </div>
            <?php endforeach; ?>
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
const CHART_LABELS = <?= json_encode(array_column($chartData,'category'), JSON_HEX_TAG) ?>;
const CHART_DATA   = <?= json_encode(array_column($chartData,'cnt'), JSON_HEX_TAG) ?>;

function updateClock() {
    const el = document.getElementById('statusTime');
    if (el) {
        let now = new Date();
        el.textContent = now.toISOString().substring(11, 19) + ' UTC';
    }
}
setInterval(updateClock, 1000); updateClock();
setInterval(() => window.location.reload(), 30000);

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

(function drawGauge() {
    const canvas = document.getElementById('gaugeCanvas'); if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const valElement = canvas.nextElementSibling;
    const val = parseInt(valElement?.dataset.target) || 0;
    const pct = val / 15; const cx = canvas.width / 2; const cy = canvas.height - 10; const r = 65;

    ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI, 2*Math.PI); ctx.strokeStyle = 'rgba(13,110,253,0.15)'; ctx.lineWidth = 14; ctx.stroke();
    if (val > 0) {
        const grad = ctx.createLinearGradient(cx - r, cy, cx + r, cy);
        grad.addColorStop(0, '#00B4D8'); grad.addColorStop(1, '#FF3B3B');
        ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI, Math.PI + (Math.PI * Math.min(1, pct))); ctx.strokeStyle = grad; ctx.lineWidth = 14; ctx.lineCap = 'round'; ctx.stroke();
        
        // Needle
        const angle = Math.PI + (Math.PI * Math.min(1, pct));
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(angle)*r, cy + Math.sin(angle)*r); ctx.strokeStyle = '#E0EEFF'; ctx.lineWidth = 3; ctx.stroke();
        ctx.beginPath(); ctx.arc(cx, cy, 6, 0, 2*Math.PI); ctx.fillStyle = '#E0EEFF'; ctx.fill();
    }
})();

document.addEventListener('DOMContentLoaded', function() {
    const canvas = document.getElementById('attackChart');
    if (canvas && typeof Chart !== 'undefined') {
        const ctx = canvas.getContext('2d');
        const grad = ctx.createLinearGradient(0, canvas.height, 0, 0);
        grad.addColorStop(0, '#0D6EFD'); grad.addColorStop(1, '#00B4D8');
        
        Chart.defaults.color = '#7BA3CC'; Chart.defaults.font.family = "'Share Tech Mono', monospace";
        new Chart(canvas, {
            type: 'bar',
            data: { labels: CHART_LABELS, datasets: [{ data: CHART_DATA, backgroundColor: grad, borderRadius: 4, hoverBackgroundColor: '#17D4BE' }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false }, tooltip: { backgroundColor: '#050F1F', borderColor: '#00B4D8', borderWidth: 1 } },
                scales: {
                    x: { grid: { color: 'rgba(13,110,253,0.1)' } },
                    y: { grid: { color: 'rgba(13,110,253,0.1)' }, beginAtZero: true }
                },
                animation: { duration: 1500, easing: 'easeOutQuart' }
            }
        });
    }

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
</script>
</body>
</html>
