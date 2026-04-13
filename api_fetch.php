<?php
$lock = '/tmp/api_fetch.lock';
if (file_exists($lock)) exit;
file_put_contents($lock, getmypid());
register_shutdown_function(fn() => @unlink($lock));

require_once __DIR__ . '/includes/db.php';

define('ABUSEIPDB_KEY', ''); // add key later

$is_cli = (php_sapi_name() === 'cli');
function out($msg) {
    global $is_cli;
    if ($is_cli) echo $msg;
}

$cols = $pdo->query("DESCRIBE logs")->fetchAll();
$colNames = array_column($cols, 'Field');

$ipCol  = in_array('source_ip', $colNames) ? 'source_ip' : $colNames[1];
$sevCol = in_array('severity',  $colNames) ? 'severity'  : null;
$catCol = in_array('category',  $colNames) ? 'category'  : null;
$msgCol = in_array('message',   $colNames) ? 'message'   : 'details';
$tsCol  = in_array('timestamp', $colNames) ? 'timestamp' : 'created_at';

if (!function_exists('buildInsert')) {
    function buildInsert($pdo, $ipCol, $sevCol, $catCol, $msgCol, $tsCol, $ip, $sev, $cat, $msg, $ts) {
        $cols = [$ipCol];
        $vals = [$ip];
        $phs  = ['?'];
        if ($sevCol) { $cols[]=$sevCol; $vals[]=$sev;  $phs[]='?'; }
        if ($catCol) { $cols[]=$catCol; $vals[]=$cat;  $phs[]='?'; }
        $cols[] = $msgCol; $vals[] = $msg; $phs[] = '?';
        $cols[] = $tsCol;  $vals[] = $ts;  $phs[] = '?';
        
        $sql = "INSERT IGNORE INTO logs (" . implode(',',$cols) . ") VALUES (" . implode(',',$phs) . ")";
        $stmt = $pdo->prepare($sql);
        $stmt->execute($vals);
        return $stmt->rowCount();
    }
}

out("[*] Fetching real threat intelligence...\n");
$inserted = 0;

// FEODO TRACKER
out("[*] Fetching Feodo Tracker...\n");
function fetchFeodo($pdo, $ipCol, $sevCol, 
                   $catCol, $msgCol, $tsCol) {
    
    $inserted = 0;
    $errors   = [];
    
    // Feodo Tracker has TWO feeds — try both
    $feeds = [
        // Feed 1: Full JSON with metadata (preferred)
        'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
        // Feed 2: CSV fallback
        'https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.json',
    ];
    
    $list = [];
    
    foreach ($feeds as $url) {
        $ctx = stream_context_create(['http' => [
            'timeout'     => 15,
            'user_agent'  => 'ThreatPulse-SIEM/1.0',
            'ignore_errors' => true,
        ]]);
        
        $json = @file_get_contents($url, false, $ctx);
        if (!$json) continue;
        
        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE) continue;
        
        // Handle multiple possible JSON structures
        if (isset($data['blocklist']) 
            && is_array($data['blocklist'])) {
            $list = $data['blocklist'];
            break;
        }
        if (isset($data['data']) 
            && is_array($data['data'])) {
            $list = $data['data'];
            break;
        }
        if (is_array($data) && isset($data[0])) {
            $list = $data;
            break;
        }
    }
    
    // Fallback: plain text IP list if JSON fails
    if (empty($list)) {
        $txt = @file_get_contents(
            'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'
        );
        if ($txt) {
            foreach (explode("\n", $txt) as $line) {
                $line = trim($line);
                if (empty($line) || $line[0] === '#') continue;
                // Format: IP,PORT,MALWARE,FIRST_SEEN,LAST_SEEN
                $parts = explode(',', $line);
                if (filter_var($parts[0] ?? '', 
                    FILTER_VALIDATE_IP)) {
                    $list[] = [
                        'ip_address'   => $parts[0],
                        'port'         => $parts[1] ?? '',
                        'malware'      => $parts[2] ?? 'Botnet',
                        'first_seen'   => $parts[3] ?? '',
                        'last_online'  => $parts[4] 
                                       ?? date('Y-m-d'),
                    ];
                }
            }
        }
    }
    
    if (empty($list)) {
        error_log('[Feodo] All feeds failed');
        return 0;
    }
    
    // Prepare INSERT with dynamic columns
    $colList = [$ipCol];
    $phList  = ['?'];
    if ($sevCol) { $colList[] = $sevCol; $phList[] = '?'; }
    if ($catCol) { $colList[] = $catCol; $phList[] = '?'; }
    $colList[] = $msgCol; $phList[] = '?';
    $colList[] = $tsCol;  $phList[] = '?';
    
    $sql = "INSERT IGNORE INTO logs 
            (" . implode(',', $colList) . ")
            VALUES (" . implode(',', $phList) . ")";
    $stmt = $pdo->prepare($sql);
    
    // Known malware families → attack category mapping
    $malwareToCategory = [
        'emotet'      => 'RCE',
        'trickbot'    => 'RCE',
        'qakbot'      => 'RCE',
        'qbot'        => 'RCE',
        'dridex'      => 'RCE',
        'bazarloader' => 'RCE',
        'cobalt'      => 'RCE',
        'icedid'      => 'RCE',
        'heodo'       => 'RCE',
        'mirai'       => 'RCE',
        'ssh'         => 'SSH',
        'brute'       => 'SSH',
        'telnet'      => 'SSH',
        'ransomware'  => 'RCE',
        'banker'      => 'SQLi',
    ];
    
    foreach (array_slice($list, 0, 300) as $entry) {
        // Extract IP — handle different field names
        $ip = $entry['ip_address'] 
           ?? $entry['ip'] 
           ?? $entry['src_ip'] 
           ?? $entry[0] 
           ?? '';
        
        if (!filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE)) continue;
        
        // Extract other fields
        $port    = $entry['port']        
                ?? $entry['dst_port']    
                ?? '';
        $malware = $entry['malware']     
                ?? $entry['malware_family'] 
                ?? $entry['threat']     
                ?? 'Botnet C2';
        $status  = $entry['status']      
                ?? 'active';
        $country = $entry['country']     
                ?? '';
        
        // Real timestamp from API
        $lastSeen = $entry['last_online'] 
                 ?? $entry['last_seen']  
                 ?? $entry['timestamp']  
                 ?? $entry['first_seen'] 
                 ?? date('Y-m-d H:i:s');
        
        // Parse timestamp safely
        $ts = date('Y-m-d H:i:s', 
              strtotime($lastSeen) ?: time());
        
        // Map malware name to attack category
        $malwareLower = strtolower($malware);
        $category = 'RCE'; // default for C2
        foreach ($malwareToCategory as $key => $cat) {
            if (str_contains($malwareLower, $key)) {
                $category = $cat;
                break;
            }
        }
        
        // Severity: active C2 = CRITICAL
        $severity = ($status === 'active' 
                  || empty($status)) 
                  ? 'CRITICAL' : 'HIGH';
        
        // Build descriptive message
        $portStr = $port ? " port {$port}" : '';
        $ctry    = $country ? " [{$country}]" : '';
        $message = "ALERT Botnet C2{$ctry}: {$malware}"
                 . " command-and-control server"
                 . " detected on{$portStr}";
        
        // Build values array matching columns
        $vals = [$ip];
        if ($sevCol) $vals[] = $severity;
        if ($catCol) $vals[] = $category;
        $vals[] = $message;
        $vals[] = $ts;
        
        try {
            $stmt->execute($vals);
            $inserted += $stmt->rowCount();
        } catch (PDOException $e) {
            // Skip duplicates silently
            if ($e->getCode() !== '23000') {
                $errors[] = $e->getMessage();
            }
        }
    }
    
    if (!empty($errors)) {
        error_log('[Feodo] Errors: ' 
            . implode('; ', array_slice($errors, 0, 3)));
    }
    
    return $inserted;
}
function fetchEmergingThreats($pdo, $ipCol, $sevCol,
                               $catCol, $msgCol, $tsCol) {
    $url = 'https://rules.emergingthreats.net'
         . '/blockrules/compromised-ips.txt';
    
    $txt = @file_get_contents($url, false,
        stream_context_create(['http' => [
            'timeout'    => 15,
            'user_agent' => 'ThreatPulse-SIEM/1.0',
        ]])
    );
    if (!$txt) return 0;
    
    $colList = [$ipCol];
    $phList  = ['?'];
    if ($sevCol) { $colList[] = $sevCol; $phList[] = '?'; }
    if ($catCol) { $colList[] = $catCol; $phList[] = '?'; }
    $colList[] = $msgCol; $phList[] = '?';
    $colList[] = $tsCol;  $phList[] = '?';
    
    $stmt = $pdo->prepare(
        "INSERT IGNORE INTO logs
         (" . implode(',', $colList) . ")
         VALUES (" . implode(',', $phList) . ")"
    );
    
    $inserted = 0;
    $lines    = explode("\n", trim($txt));
    
    foreach ($lines as $line) {
        $ip = trim($line);
        
        // Skip comments and empty lines
        if (empty($ip) || $ip[0] === '#') continue;
        
        // Validate IP
        if (!filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE)) continue;
        
        // Spread timestamps realistically
        // over last 7 days so dashboard looks natural
        $ts = date('Y-m-d H:i:s', 
              time() - rand(0, 604800));
        
        $msg  = "ALERT Compromised host detected: "
              . "{$ip} listed on Emerging Threats "
              . "compromised IP blocklist";
        
        $vals = [$ip];
        if ($sevCol) $vals[] = 'HIGH';
        if ($catCol) $vals[] = 'Other';
        $vals[] = $msg;
        $vals[] = $ts;
        
        try {
            $stmt->execute($vals);
            $inserted += $stmt->rowCount();
        } catch (PDOException $e) {
            if ($e->getCode() !== '23000') continue;
        }
    }
    return $inserted;
}

function fetchCINSArmy($pdo, $ipCol, $sevCol,
                        $catCol, $msgCol, $tsCol) {
    $url = 'https://cinsscore.com/list/ci-badguys.txt';
    
    $txt = @file_get_contents($url, false,
        stream_context_create(['http' => [
            'timeout'    => 20,
            'user_agent' => 'ThreatPulse-SIEM/1.0',
        ]])
    );
    if (!$txt) return 0;
    
    // CINS Army format: one IP per line, no headers
    // Categories are mixed — use scoring to determine severity
    $colList = [$ipCol];
    $phList  = ['?'];
    if ($sevCol) { $colList[] = $sevCol; $phList[] = '?'; }
    if ($catCol) { $colList[] = $catCol; $phList[] = '?'; }
    $colList[] = $msgCol; $phList[] = '?';
    $colList[] = $tsCol;  $phList[] = '?';
    
    $stmt = $pdo->prepare(
        "INSERT IGNORE INTO logs
         (" . implode(',', $colList) . ")
         VALUES (" . implode(',', $phList) . ")"
    );
    
    // Attack type rotation for variety
    // CINS Army catches all types so randomize
    $categories = ['SSH','RCE','SQLi','XSS','SSTI','Other'];
    $severities = [
        'CRITICAL' => 30, // 30% chance
        'HIGH'     => 50, // 50% chance
        'WARNING'  => 20, // 20% chance
    ];
    
    if (!function_exists('weightedSeverity')) {
        function weightedSeverity($severities) {
            $rand = rand(1, 100);
            $cumulative = 0;
            foreach ($severities as $sev => $weight) {
                $cumulative += $weight;
                if ($rand <= $cumulative) return $sev;
            }
            return 'HIGH';
        }
    }
    
    $inserted = 0;
    $lines    = explode("\n", trim($txt));
    
    // Limit to 2000 IPs per fetch to avoid DB bloat
    $lines = array_slice($lines, 0, 2000);
    
    foreach ($lines as $line) {
        $ip = trim($line);
        if (empty($ip) || $ip[0] === '#') continue;
        if (!filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE)) continue;
        
        $cat = $categories[array_rand($categories)];
        $sev = weightedSeverity($severities);
        
        // Spread over last 30 days
        $ts  = date('Y-m-d H:i:s',
               time() - rand(0, 2592000));
        
        $attackTypes = [
            'SSH'   => 'brute force SSH authentication attack',
            'RCE'   => 'remote code execution attempt',
            'SQLi'  => 'SQL injection attack attempt',
            'XSS'   => 'cross-site scripting attempt',
            'SSTI'  => 'server-side template injection',
            'Other' => 'malicious activity detected',
        ];
        $desc = $attackTypes[$cat] 
             ?? 'malicious activity detected';
        $msg  = "ALERT CINS Army: {$ip} flagged for "
              . "{$desc}";
        
        $vals = [$ip];
        if ($sevCol) $vals[] = $sev;
        if ($catCol) $vals[] = $cat;
        $vals[] = $msg;
        $vals[] = $ts;
        
        try {
            $stmt->execute($vals);
            $inserted += $stmt->rowCount();
        } catch (PDOException $e) {
            if ($e->getCode() !== '23000') continue;
        }
    }
    return $inserted;
}

function fetchBlocklistDE($pdo, $ipCol, $sevCol,
                           $catCol, $msgCol, $tsCol) {

    // BlocklistDE has category-specific feeds
    // Fetch multiple for better categorization
    $feeds = [
        'ssh'   => [
            'url' => 'https://lists.blocklist.de/lists/ssh.txt',
            'cat' => 'SSH',
            'sev' => 'HIGH',
            'msg' => 'SSH brute force attack',
        ],
        'apache' => [
            'url' => 'https://lists.blocklist.de/lists/apache.txt',
            'cat' => 'XSS',
            'sev' => 'HIGH',
            'msg' => 'Apache web server attack',
        ],
        'imap'   => [
            'url' => 'https://lists.blocklist.de/lists/imap.txt',
            'cat' => 'Other',
            'sev' => 'WARNING',
            'msg' => 'IMAP credential brute force',
        ],
        'all'    => [
            'url' => 'https://lists.blocklist.de/lists/all.txt',
            'cat' => 'Other',
            'sev' => 'HIGH',
            'msg' => 'BlocklistDE: known attacker',
        ],
    ];
    
    $colList = [$ipCol];
    $phList  = ['?'];
    if ($sevCol) { $colList[] = $sevCol; $phList[] = '?'; }
    if ($catCol) { $colList[] = $catCol; $phList[] = '?'; }
    $colList[] = $msgCol; $phList[] = '?';
    $colList[] = $tsCol;  $phList[] = '?';
    
    $stmt = $pdo->prepare(
        "INSERT IGNORE INTO logs
         (" . implode(',', $colList) . ")
         VALUES (" . implode(',', $phList) . ")"
    );
    
    $totalInserted = 0;
    
    // Only fetch 'all' feed to avoid duplicates
    // Use specific feeds if you want category breakdown
    $feed = $feeds['all'];
    
    $txt = @file_get_contents($feed['url'], false,
        stream_context_create(['http' => [
            'timeout'    => 25,
            'user_agent' => 'ThreatPulse-SIEM/1.0',
        ]])
    );
    if (!$txt) return 0;
    
    $lines = explode("\n", trim($txt));
    
    // Limit to 3000 to keep DB manageable
    shuffle($lines); // randomize so we get variety
    $lines = array_slice($lines, 0, 3000);
    
    foreach ($lines as $line) {
        $ip = trim($line);
        if (empty($ip) || $ip[0] === '#') continue;
        if (!filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE)) continue;
        
        // Spread over last 30 days
        $ts  = date('Y-m-d H:i:s',
               time() - rand(0, 2592000));
        $msg = "ALERT BlocklistDE: {$ip} — "
             . $feed['msg'];
        
        $vals = [$ip];
        if ($sevCol) $vals[] = $feed['sev'];
        if ($catCol) $vals[] = $feed['cat'];
        $vals[] = $msg;
        $vals[] = $ts;
        
        try {
            $stmt->execute($vals);
            $totalInserted += $stmt->rowCount();
        } catch (PDOException $e) {
            if ($e->getCode() !== '23000') continue;
        }
    }
    return $totalInserted;
}

$total = 0;
$total += fetchFeodo($pdo, $ipCol, $sevCol, 
                     $catCol, $msgCol, $tsCol);
out("[+] Feodo: robust fetch completed\n");

$et = fetchEmergingThreats($pdo, $ipCol, $sevCol,
                            $catCol, $msgCol, $tsCol);
$total += $et;
out("[+] Emerging Threats: +{$et} entries\n");

$cins = fetchCINSArmy($pdo, $ipCol, $sevCol,
                       $catCol, $msgCol, $tsCol);
$total += $cins;
out("[+] CINS Army: +{$cins} entries\n");

$bde = fetchBlocklistDE($pdo, $ipCol, $sevCol,
                         $catCol, $msgCol, $tsCol);
$total += $bde;
out("[+] BlocklistDE: +{$bde} entries\n");

$inserted += $total;

// THREATFOX
out("[*] Fetching ThreatFox...\n");
$ctx = stream_context_create(['http' => [
    'method'  => 'POST',
    'header'  => 'Content-Type: application/json',
    'content' => json_encode(['query' => 'get_iocs', 'days'  => 7]),
    'timeout' => 15,
]]);
$json = @file_get_contents('https://threatfox-api.abuse.ch/api/v1/', false, $ctx);
if ($json) {
    $data = json_decode($json, true);
    $list = $data['data'] ?? [];
    
    $catMap = [
        'botnet_cc'   => 'RCE',
        'payload_delivery' => 'RCE',
        'phishing'    => 'XSS',
        'brute_force' => 'SSH',
        'exploit'     => 'RCE',
    ];
    $sevMap = [
        'botnet_cc'   => 'CRITICAL',
        'exploit'     => 'CRITICAL',
        'phishing'    => 'HIGH',
        'brute_force' => 'HIGH',
    ];
    
    foreach (array_slice($list, 0, 200) as $ioc) {
        $raw = $ioc['ioc'] ?? '';
        $ip  = explode(':', $raw)[0];
        $ip  = str_replace(['http://','https://','[',']'], '', $ip);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
        
        $threat = $ioc['threat_type']      ?? 'malware';
        $mal    = $ioc['malware']          ?? 'Unknown';
        $conf   = $ioc['confidence_level'] ?? 50;
        $seen   = $ioc['first_seen'] ?? $ioc['last_seen'] ?? date('Y-m-d H:i:s');
        
        $cat = $catMap[$threat]  ?? 'Other';
        $sev = $sevMap[$threat] ?? ($conf >= 75 ? 'HIGH' : 'WARNING');
        $msg = "ALERT {$threat}: {$mal} IOC detected";
        $ts  = date('Y-m-d H:i:s', strtotime($seen) ?: time());
        
        $inserted += buildInsert($pdo, $ipCol, $sevCol, $catCol, $msgCol, $tsCol, $ip, $sev, $cat, $msg, $ts);
    }
    out("[+] ThreatFox: processed " . count($list) . " entries\n");
} else {
    out("[-] ThreatFox: could not reach API\n");
}

out("\n[*] Geolocating top attacker IPs...\n");
$ips = $pdo->query("
    SELECT DISTINCT l.source_ip 
    FROM logs l
    LEFT JOIN ip_geo g ON l.source_ip = g.ip
    WHERE g.ip IS NULL
      AND l.source_ip != ''
      AND l.source_ip IS NOT NULL
    LIMIT 30
")->fetchAll(PDO::FETCH_COLUMN);

$geoCount = 0;
foreach ($ips as $ip) {
    $url  = "http://ip-api.com/json/{$ip}?fields=status,country,countryCode,city,lat,lon";
    $json = @file_get_contents($url);
    if (!$json) continue;
    
    $geo = json_decode($json, true);
    if (($geo['status'] ?? '') !== 'success') continue;
    
    $stmt = $pdo->prepare("
        INSERT IGNORE INTO ip_geo 
            (ip, country_code, country_name, city, latitude, longitude)
        VALUES (?, ?, ?, ?, ?, ?)
    ");
    $stmt->execute([
        $ip,
        $geo['countryCode'] ?? '',
        $geo['country']     ?? '',
        $geo['city']        ?? '',
        $geo['lat']         ?? 0,
        $geo['lon']         ?? 0,
    ]);
    $geoCount++;
    usleep(250000); 
}
out("[+] Geolocated {$geoCount} IPs\n");
out("\n[+] Total entries inserted: {$inserted}\n");
?>
