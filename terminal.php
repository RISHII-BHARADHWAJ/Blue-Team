<?php
session_name('CYBERTECH_SECURE_SESSION');
session_start();
if (empty($_SESSION['analyst'])) {
    header('Location: login.php'); exit;
}

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header_remove('X-Powered-By');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf_ok = hash_equals(
        $_SESSION['csrf_token'] ?? '',
        $_POST['csrf_token'] ?? ''
    );
    if ($csrf_ok && !empty($_POST['token'])) {
        $token_data = $_SESSION['terminal_tokens'][$_POST['token']] ?? null;
        if ($token_data && time() <= $token_data['expires']) {
            $_SESSION['terminal_ip'] = $token_data['ip'];
            unset($_SESSION['terminal_tokens'][$_POST['token']]);
        }
    }
}

$target_ip = $_SESSION['terminal_ip'] ?? null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>System Terminal | Blue Team SOC</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
:root {
    --green:  #00FF9C;
    --cyan:   #00D4FF;
    --amber:  #FFB700;
    --red:    #FF3B3B;
    --white:  #E8F4FF;
    --muted:  #4A7A9B;
    --purple: #BD93F9;
    --bg:     #020B18;
    --bg2:    #050F1F;
    --border: rgba(0,180,216,0.2);
    --prompt: #00D4FF;
}

* { box-sizing:border-box; margin:0; padding:0; }

body {
    background: var(--bg);
    color: var(--green);
    font-family: 'Share Tech Mono', 'Courier New', monospace;
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    position: relative;
}

/* Scanlines overlay */
body::before {
    content: '';
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 0, 0, 0.08) 2px,
        rgba(0, 0, 0, 0.08) 4px
    );
    pointer-events: none;
    z-index: 9999;
}

/* Subtle vignette — dark edges, bright center */
body::after {
    content: '';
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: radial-gradient(
        ellipse at center,
        transparent 60%,
        rgba(0, 0, 0, 0.6) 100%
    );
    pointer-events: none;
    z-index: 9998;
}

/* Very subtle screen flicker animation */
@keyframes flicker {
    0%   { opacity: 1;    }
    92%  { opacity: 1;    }
    93%  { opacity: 0.96; }
    94%  { opacity: 1;    }
    96%  { opacity: 0.98; }
    100% { opacity: 1;    }
}

/* WINDOW CHROME — macOS style */
.window-bar {
    background: var(--bg2);
    padding: 10px 16px;
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    position: relative;
    z-index: 10;
}
.dot {
    width: 13px; height: 13px;
    border-radius: 50%;
    cursor: pointer;
}
.dot-red    { background: #FF5F57; }
.dot-yellow { background: #FFBD2E; }
.dot-green  { background: #28CA41; }
.window-title {
    color: var(--cyan);
    font-size: 0.88rem;
    margin-left: 8px;
    letter-spacing: 1px;
    text-shadow: 0 0 8px rgba(0, 212, 255, 0.5);
}

/* TERMINAL BODY */
.terminal-body {
    flex: 1;
    overflow-y: auto;
    padding: 20px 24px 10px;
    background: var(--bg);
    scroll-behavior: smooth;
    font-size: 0.95rem;
    animation: flicker 8s infinite;
    position: relative;
    z-index: 10;
}
.terminal-body::-webkit-scrollbar { width: 4px; }
.terminal-body::-webkit-scrollbar-track { background: var(--bg); }
.terminal-body::-webkit-scrollbar-thumb { 
    background: var(--cyan); border-radius: 2px; }

/* OUTPUT LINES */
.line { 
    line-height: 1.8; 
    font-size: 0.95rem;
    white-space: pre-wrap;
    word-break: break-all;
}
.line-header  { color: var(--white); font-weight: bold; }
.line-success { color: var(--green); text-shadow: 0 0 8px rgba(0, 255, 156, 0.4); } 
.line-info    { color: var(--cyan); }
.line-warning { color: var(--amber); text-shadow: 0 0 8px rgba(255, 183, 0, 0.4); }
.line-error   { color: var(--red); text-shadow: 0 0 8px rgba(255, 59, 59, 0.5); }
.line-data    { color: var(--green); }
.line-label   { color: var(--muted); }
.line-title   { 
    color: var(--white); 
    font-weight: bold; 
    letter-spacing: 2px; 
    text-shadow: 0 0 10px rgba(0, 212, 255, 0.8), 0 0 20px rgba(0, 212, 255, 0.4), 0 0 40px rgba(0, 212, 255, 0.2);
}
.line-blank   { height: 10px; display: block; }
.line-cmd     { color: var(--white); font-weight: bold; }
.line-mitre   { color: var(--purple); }

/* INPUT BAR */
.input-bar {
    display: flex;
    align-items: center;
    padding: 12px 24px;
    background: var(--bg);
    border-top: 1px solid var(--border);
    flex-shrink: 0;
    position: relative;
    cursor: text;
    z-index: 10;
}
.prompt {
    color: var(--prompt);
    font-size: 0.95rem;
    margin-right: 2px;
    white-space: nowrap;
    font-family: 'Share Tech Mono', monospace;
    text-shadow: 0 0 10px rgba(0, 212, 255, 0.6);
}
#termInput {
    position: absolute;
    opacity: 0;
    left: 0; top: 0;
    width: 100%; height: 100%;
    caret-color: transparent;
    font-size: 0.95rem;
    font-family: 'Share Tech Mono', monospace;
}
#termInput:focus {
    text-shadow: 0 0 6px rgba(232, 244, 255, 0.3);
}

#inputMirror {
    color: var(--white);
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.95rem;
    white-space: pre;
}

.cursor-block {
    display: inline-block;
    width: 9px;
    height: 1.1em;
    background: var(--cyan);
    margin-left: 1px;
    vertical-align: text-bottom;
    box-shadow: 0 0 8px rgba(0, 212, 255, 0.8);
    animation: cursorBlink 1s step-end infinite;
}

@keyframes cursorBlink {
    0%, 100% { opacity: 1; }
    50%      { opacity: 0; }
}

/* Progress bar styles */
.progress-wrap {
    margin: 6px 0;
    width: 300px;
}
.progress-label {
    color: var(--muted);
    font-size: 0.8rem;
    margin-bottom: 3px;
}
.progress-track {
    background: rgba(0, 180, 216, 0.1);
    border: 1px solid rgba(0, 180, 216, 0.2);
    border-radius: 2px;
    height: 8px;
    overflow: hidden;
}
.progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #0D6EFD, var(--cyan));
    border-radius: 2px;
    width: 0%;
    box-shadow: 0 0 10px rgba(0, 212, 255, 0.6);
    transition: width 0.1s linear;
}
</style>
</head>
<body>

<!-- WINDOW BAR -->
<div class="window-bar">
    <div class="dot dot-red" onclick="window.location='dashboard.php'"></div>
    <div class="dot dot-yellow"></div>
    <div class="dot dot-green"></div>
    <span class="window-title">SOC Investigative Terminal // NODE-01</span>
</div>

<!-- TERMINAL OUTPUT -->
<div class="terminal-body" id="termOutput">
    <div class="line line-title">═══ Blue Team SOC Terminal v3.0 ═══</div>
    <div class="line line-blank"></div>
    <div class="line line-info">[*] Accessing threat intelligence network...</div>
    <div class="line line-success">[+] Connected successfully. Type 'help' for available commands.</div>
    <div class="line line-blank"></div>

    <?php if ($target_ip): ?>
    <div class="line line-cmd"><span class="prompt">analyst@soc:~$</span> analyze <?= htmlspecialchars($target_ip) ?></div>
    <div class="line line-blank" id="autoAnalyzeAnchor"></div>
    <?php endif; ?>
</div>

<!-- INPUT BAR -->
<div class="input-bar">
    <span class="prompt">analyst@soc:~$&nbsp;</span>
    <span id="inputMirror"></span>
    <span class="cursor-block" id="cursor"></span>
    <input type="text" id="termInput" 
           autocomplete="off" autocorrect="off"
           autocapitalize="off" spellcheck="false"
           placeholder="">
</div>

<script>
// ── DATA ──────────────────────────────
const TARGET_IP = <?= json_encode($target_ip) ?>;

const COMMANDS = [
    'help','clear','analyze','scan','whois',
    'geolocate','block','unblock','history','exit'
];

let cmdHistory = [];
let histIdx = -1;

// ── FOCUS & MIRROR ─────────────────────
const input  = document.getElementById('termInput');
const output = document.getElementById('termOutput');
const mirror = document.getElementById('inputMirror');

document.addEventListener('click', () => input.focus());
input.focus();

input.addEventListener('input', function() {
    mirror.textContent = this.value;
});

function syncInput() {
    mirror.textContent = input.value;
}

// ── PRINT HELPERS ─────────────────────
function print(text, cls='line-success') {
    const d = document.createElement('div');
    d.className = 'line ' + cls;
    d.textContent = text;
    output.appendChild(d);
    scrollBottom();
}
function blank() {
    const d = document.createElement('div');
    d.className = 'line line-blank';
    output.appendChild(d);
}
function scrollBottom() {
    output.scrollTop = output.scrollHeight;
}

function typewriterLine(text, cls, callback) {
    const d = document.createElement('div');
    d.className = 'line ' + cls;
    d.textContent = '';
    output.appendChild(d);
    scrollBottom();

    if (!text.trim()) {
        d.className = 'line line-blank';
        if (callback) callback();
        return;
    }

    const speed = cls.includes('title') ? 25 : cls.includes('data') ? 18 : 22;

    let i = 0;
    const timer = setInterval(() => {
        d.textContent += text[i];
        scrollBottom();
        i++;
        if (i >= text.length) {
            clearInterval(timer);
            if (callback) callback();
        }
    }, speed);
}

function printLines(lines, delay=0, callback=null) {
    let i = 0;
    function next() {
        if (i >= lines.length) {
            if (callback) callback();
            return;
        }
        const [text, cls] = lines[i++];
        typewriterLine(text, cls || 'line-success', next);
    }
    next();
}

function showProgress(label, duration, callback) {
    const wrap = document.createElement('div');
    wrap.className = 'progress-wrap';
    const lbl = document.createElement('div');
    lbl.className = 'progress-label';
    lbl.textContent = label;
    const track = document.createElement('div');
    track.className = 'progress-track';
    const fill = document.createElement('div');
    fill.className = 'progress-fill';
    track.appendChild(fill);
    wrap.appendChild(lbl);
    wrap.appendChild(track);
    output.appendChild(wrap);
    scrollBottom();

    let pct = 0;
    const steps = 40;
    const interval = duration / steps;
    const timer = setInterval(() => {
        pct += (100 / steps);
        const eased = pct < 80 ? pct * 1.1 : 80 + (pct - 80) * 0.5;
        fill.style.width = Math.min(eased, 98) + '%';
        if (pct >= 100) {
            clearInterval(timer);
            fill.style.width = '100%';
            setTimeout(() => {
                wrap.remove();
                if (callback) callback();
            }, 200);
        }
    }, interval);
}

// ── SEED RANDOM ───────────────────────
function seedRand(ip) {
    return ip.split('.').reduce((a,b) => a + parseInt(b), 0);
}
function seededRandom(seed, i) {
    const x = Math.sin(seed + i) * 10000;
    return x - Math.floor(x);
}

// ── COMMANDS ──────────────────────────
function runCommand(raw) {
    const parts = raw.trim().split(/\s+/);
    const cmd   = parts[0].toLowerCase();
    const arg   = parts[1] || '';

    const d = document.createElement('div');
    d.className = 'line line-cmd';
    d.innerHTML = '<span class="prompt">analyst@soc:~$</span> ' + raw;
    output.appendChild(d);
    blank();

    input.disabled = true;

    const finishCmd = () => {
        input.disabled = false;
        input.focus();
        scrollBottom();
    };

    switch(cmd) {
        case 'help':
            printLines([
                ['', ''],
                ['═══ Available Commands: ═══', 'line-title'],
                ['', ''],
                ['  analyze  <IP>   Threat intelligence report', 'line-info'],
                ['  scan     <IP>   Port scan (Nmap style)',     'line-info'],
                ['  whois    <IP>   WHOIS lookup',               'line-info'],
                ['  geolocate <IP>  Geolocation data',           'line-info'],
                ['  block    <IP>   Add IP to blocklist',        'line-info'],
                ['  unblock  <IP>   Remove from blocklist',      'line-info'],
                ['  history         Recently analyzed IPs',      'line-info'],
                ['  clear           Clear terminal',             'line-info'],
                ['  exit            Return to dashboard',        'line-info'],
                ['', '']
            ], 0, finishCmd);
            break;

        case 'clear':
            output.innerHTML = '';
            finishCmd();
            break;

        case 'exit':
            window.location.href = 'dashboard.php';
            break;

        case 'analyze':
            if (!arg) { print('[-] Usage: analyze <IP>', 'line-error'); blank(); finishCmd(); break; }
            if (!isValidIP(arg)) { print('[-] Invalid IP format: ' + arg, 'line-error'); blank(); finishCmd(); break; }
            doAnalyze(arg, finishCmd);
            break;

        case 'scan':
            if (!arg) { print('[-] Usage: scan <IP>', 'line-error'); blank(); finishCmd(); break; }
            if (!isValidIP(arg)) { print('[-] Invalid IP format.', 'line-error'); blank(); finishCmd(); break; }
            doScan(arg, finishCmd);
            break;

        case 'whois':
            if (!arg) { print('[-] Usage: whois <IP>', 'line-error'); blank(); finishCmd(); break; }
            doWhois(arg, finishCmd);
            break;

        case 'geolocate':
            if (!arg) { print('[-] Usage: geolocate <IP>', 'line-error'); blank(); finishCmd(); break; }
            doGeolocate(arg, finishCmd);
            break;

        case 'block':
            if (!arg) { print('[-] Usage: block <IP>', 'line-error'); blank(); finishCmd(); break; }
            printLines([
                ['[*] Adding ' + arg + ' to blocklist...', 'line-info'],
                ['[+] IP ' + arg + ' blocked successfully.', 'line-success'],
                ['[+] Firewall rule applied. Traffic dropped.', 'line-success'],
                ['', '']
            ], 0, finishCmd);
            break;

        case 'unblock':
            if (!arg) { print('[-] Usage: unblock <IP>', 'line-error'); blank(); finishCmd(); break; }
            printLines([
                ['[*] Removing ' + arg + ' from blocklist...','line-info'],
                ['[+] IP ' + arg + ' unblocked.', 'line-success'],
                ['', '']
            ], 0, finishCmd);
            break;

        case 'history':
            if (cmdHistory.length === 0) {
                print('[*] No commands in history.', 'line-info');
                blank();
                finishCmd();
            } else {
                let lines = [
                    ['', ''],
                    ['═══ Command History ═══', 'line-title'],
                    ['', '']
                ];
                cmdHistory.slice(-15).forEach((c,i) => {
                    lines.push(['  ' + (i+1) + '.  ' + c, 'line-info']);
                });
                lines.push(['', '']);
                printLines(lines, 0, finishCmd);
            }
            break;

        default:
            print('[!] Unknown command: \'' + cmd + '\'. Type \'help\' for commands.', 'line-warning');
            blank();
            finishCmd();
    }
}

// ── ANALYZE ───────────────────────────
function doAnalyze(ip, callback) {
    const seed = seedRand(ip);
    const score = 40 + Math.floor(seededRandom(seed,1)*55);
    const level = score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW';
    const lvlCls = score >= 75 ? 'line-error' : score >= 50 ? 'line-warning' : 'line-success';

    const isps = ['DigitalOcean LLC','Linode LLC','OVH SAS','Hetzner Online GmbH','Alibaba Cloud','Amazon AWS'];
    const locs = ['Frankfurt, Germany','Amsterdam, Netherlands','Singapore','Shanghai, China','Moscow, Russia','São Paulo, Brazil'];
    const asns = ['AS14061','AS63949','AS16276','AS24940','AS37963','AS16509'];

    const iIdx = Math.floor(seededRandom(seed,2)*isps.length);
    const isp  = isps[iIdx];
    const loc  = locs[iIdx];
    const asn  = asns[iIdx];
    const conf = 85 + Math.floor(seededRandom(seed,3)*13);

    const allAnomalies = [
        'Matches known botnet signature (Mirai Variant)',
        'High frequency port scanning detected (22,23,80)',
        'Multiple failed SSH authentication attempts',
        'Correlated with CVE-2023-XXXX exploit attempts',
        'Known Tor exit node',
        'Listed on AbuseIPDB (score: 97%)',
        'Reverse DNS mismatch detected',
        'Associated with credential stuffing campaign',
    ];
    const anomCount = 3 + Math.floor(seededRandom(seed,4)*3);
    const anomalies = allAnomalies.filter((_,i) => seededRandom(seed,i+10) > 0.45).slice(0, anomCount);

    const actions = [
        'Block subnet ' + ip.split('.').slice(0,3).join('.') + '.0/24 immediately.',
        'Reset credentials for potentially compromised accounts.',
        'Patch all SSH services to latest version.',
        'Review firewall rules for port 22 exposure.',
        'Check for lateral movement indicators in internal logs.',
    ];

    const lines = [
        ['', ''],
        ['═══ THREAT INTELLIGENCE REPORT ═══', 'line-title'],
        ['', ''],
        ['Target:       ' + ip, 'line-data'],
        ['Risk Score:   ' + score + '/100 (' + level + ')', lvlCls],
        ['Confidence:   ' + conf + '%', 'line-data'],
        ['ISP:          ' + isp, 'line-data'],
        ['Location:     ' + loc, 'line-data'],
        ['ASN:          ' + asn, 'line-data'],
        ['', ''],
        ['═══ DETECTED ANOMALIES ═══', 'line-title'],
        ['', ''],
        ...anomalies.map(a => ['[!] ' + a, 'line-warning']),
        ['', ''],
        ['═══ RECOMMENDED ACTIONS ═══', 'line-title'],
        ['', ''],
        ...actions.slice(0,3).map((a,i) => [(i+1) + '. ' + a, 'line-success']),
        ['', ''],
        ['[+] Analysis complete.', 'line-success'],
        ['', ''],
    ];

    showProgress('Querying threat intelligence...', 1000, () => {
        showProgress('Correlating attack patterns...', 600, () => {
            printLines(lines, 0, callback);
        });
    });
}

// ── SCAN ──────────────────────────────
function doScan(ip, callback) {
    const seed = seedRand(ip);
    const basePorts = [[22,'tcp','ssh','OpenSSH 8.2p1'], [80,'tcp','http','Apache 2.4.54']];
    const optPorts  = [
        [443,'tcp','https',''], [21,'tcp','ftp','vsftpd 3.0.5'], [3306,'tcp','mysql','MySQL 8.0.31'],
        [3389,'tcp','rdp','Microsoft RDS'], [6379,'tcp','redis','Redis 7.0.5'], [8080,'tcp','http-alt','nginx 1.24.0'],
        [5432,'tcp','postgresql','PostgreSQL 14'], [27017,'tcp','mongodb','MongoDB 6.0']
    ];
    const open = [...basePorts, ...optPorts.filter((_,i) => seededRandom(seed,i+20) > 0.55)];
    const riskyPorts = [3306,3389,6379,27017,21,23];
    const secs = (1.8 + seededRandom(seed,99)*3.1).toFixed(2);

    const osOptions = ['Linux 5.x (97% confidence)', 'Linux 4.x (93% confidence)', 'Windows Server 2019 (88% confidence)', 'FreeBSD 13.x (91% confidence)'];
    const os = osOptions[Math.floor(seededRandom(seed,50)*osOptions.length)];

    let lines = [
        ['', ''],
        ['═══ NMAP SCAN RESULTS FOR ' + ip + ' ═══', 'line-title'],
        ['', ''],
        ['PORT        STATE   SERVICE', 'line-label'],
    ];

    open.forEach(([port,proto,svc,ver]) => {
        const isRisky = riskyPorts.includes(port);
        const cls = isRisky ? 'line-warning' : 'line-success';
        const pfx = isRisky ? '[!]' : '[+]';
        const v   = ver ? ' (' + ver + ')' : '';
        lines.push([pfx + ' ' + (port+'/'+proto).padEnd(12) + 'open    ' + svc + v, cls]);
    });

    lines = lines.concat([
        ['', ''],
        ['[*] OS Detection: ' + os, 'line-info'],
        ['[+] Nmap done: 1 IP address scanned in ' + secs + ' seconds.', 'line-success'],
        ['', ''],
        ['═══ RISK ASSESSMENT ═══', 'line-title'],
        ['', ''],
        ...open.filter(([p]) => riskyPorts.includes(p)).map(([p,,s]) => ['[!] HIGH RISK: Port ' + p + ' (' + s + ') exposed to internet', 'line-error']),
        ['', ''],
    ]);

    showProgress('Initiating SYN stealth scan...', 1000, () => {
        showProgress('Scanning 1000 ports...', 1000, () => {
            printLines(lines, 0, callback);
        });
    });
}

// ── WHOIS ─────────────────────────────
function doWhois(ip, callback) {
    const seed = seedRand(ip);
    const orgs = ['DigitalOcean LLC','Hetzner Online GmbH','OVH SAS','Linode LLC'];
    const org  = orgs[Math.floor(seededRandom(seed,1)*orgs.length)];
    const yr   = 2018 + Math.floor(seededRandom(seed,2)*6);
    
    showProgress('Querying WHOIS registries...', 800, () => {
        printLines([
            ['', ''],
            ['═══ WHOIS RESULTS ═══', 'line-title'],
            ['', ''],
            ['IP Address:   ' + ip,    'line-data'],
            ['Organisation: ' + org,   'line-data'],
            ['Network:      ' + ip.split('.').slice(0,3).join('.') + '.0/24', 'line-data'],
            ['Country:      DE',       'line-data'],
            ['Registered:   ' + yr,    'line-data'],
            ['Abuse Email:  abuse@' + org.toLowerCase().replace(/ /g,'').replace('llc','').replace('gmbh','') + '.com', 'line-data'],
            ['', ''],
        ], 0, callback);
    });
}

// ── GEOLOCATE ─────────────────────────
function doGeolocate(ip, callback) {
    const seed = seedRand(ip);
    const locs = [
        {city:'Frankfurt',country:'Germany',cc:'DE',lat:'50.1109',lon:'8.6821'},
        {city:'Amsterdam',country:'Netherlands',cc:'NL',lat:'52.3676',lon:'4.9041'},
        {city:'Singapore',country:'Singapore',cc:'SG',lat:'1.3521', lon:'103.8198'},
        {city:'Shanghai',country:'China',cc:'CN',lat:'31.2304',lon:'121.4737'},
    ];
    const loc = locs[Math.floor(seededRandom(seed,1)*locs.length)];
    showProgress('Tracing route and resolving IP...', 1000, () => {
        printLines([
            ['', ''],
            ['═══ GEOLOCATION ═══', 'line-title'],
            ['', ''],
            ['IP:         ' + ip, 'line-data'],
            ['City:       ' + loc.city, 'line-data'],
            ['Country:    ' + loc.country + ' (' + loc.cc + ')', 'line-data'],
            ['Latitude:   ' + loc.lat, 'line-data'],
            ['Longitude:  ' + loc.lon, 'line-data'],
            ['Timezone:   UTC+1', 'line-data'],
            ['', ''],
        ], 0, callback);
    });
}

// ── VALIDATION ────────────────────────
function isValidIP(ip) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
        ip.split('.').every(o => parseInt(o) <= 255);
}

// ── KEYBOARD ──────────────────────────
input.addEventListener('keydown', function(e) {
    if (this.disabled) { e.preventDefault(); return; }

    if (e.key === 'Enter') {
        e.preventDefault();
        const val = this.value.trim();
        if (!val) return;
        cmdHistory.push(val);
        histIdx = -1;
        this.value = '';
        syncInput();
        runCommand(val);
    }
    else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (histIdx < cmdHistory.length - 1) {
            histIdx++;
            this.value = cmdHistory[cmdHistory.length - 1 - histIdx];
            syncInput();
        }
    }
    else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (histIdx > 0) {
            histIdx--;
            this.value = cmdHistory[cmdHistory.length - 1 - histIdx];
            syncInput();
        } else {
            histIdx = -1;
            this.value = '';
            syncInput();
        }
    }
    else if (e.key === 'Tab') {
        e.preventDefault();
        const v = this.value;
        const match = COMMANDS.find(c => c.startsWith(v));
        if (match) { this.value = match + ' '; syncInput(); }
    }
    else if (e.key === 'l' && e.ctrlKey) {
        e.preventDefault();
        output.innerHTML = '';
        this.value = '';
        syncInput();
    }
    else if (e.key === 'c' && e.ctrlKey) {
        e.preventDefault();
        const d = document.createElement('div');
        d.className = 'line line-cmd';
        d.innerHTML = '<span class="prompt">analyst@soc:~$</span> ' + this.value + '<span class="line-error">^C</span>';
        output.appendChild(d);
        blank();
        this.value = '';
        syncInput();
        scrollBottom();
    }
});

// ── AUTO-ANALYZE ON LOAD ───────────────
if (TARGET_IP) {
    input.disabled = true;
    setTimeout(() => {
        const anc = document.getElementById('autoAnalyzeAnchor');
        if (anc) anc.remove();
        doAnalyze(TARGET_IP, () => {
            input.disabled = false;
            input.focus();
        });
    }, 400);
}
</script>
</body>
</html>
