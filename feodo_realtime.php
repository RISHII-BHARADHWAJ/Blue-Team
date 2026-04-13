<?php
// feodo_realtime.php
// Fetches ONLY Feodo Tracker — runs every 5 minutes
// Designed to be lightweight and fast

$db_host = getenv('DB_HOST') ?: 'localhost';
$pdo = new PDO(
    "mysql:host={$db_host};dbname=cybertech_db;charset=utf8mb4",
    'redteam_user', 'root',
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]
);

// Lock file — prevent overlapping runs
$lock = '/tmp/feodo_realtime.lock';
if (file_exists($lock) 
    && (time() - filemtime($lock)) < 240) {
    exit('[Feodo] Already running, skipping.' . PHP_EOL);
}
file_put_contents($lock, getmypid());
register_shutdown_function(fn() => @unlink($lock));

$start = microtime(true);

// Detect actual column names
$cols    = $pdo->query("DESCRIBE logs")->fetchAll();
$colNames = array_column($cols, 'Field');
$ipCol   = in_array('source_ip', $colNames) ? 'source_ip' : 'ip';
$sevCol  = in_array('severity',  $colNames) ? 'severity'  : null;
$catCol  = in_array('category',  $colNames) ? 'category'  : null;
$msgCol  = in_array('message',   $colNames) ? 'message'   : 'details';
$tsCol   = in_array('timestamp', $colNames) ? 'timestamp' : 'created_at';

// Fetch from Feodo Tracker
$json = @file_get_contents(
    'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
    false,
    stream_context_create(['http' => [
        'timeout'    => 10,
        'user_agent' => 'ThreatPulse-SIEM/1.0',
    ]])
);

$inserted = 0;

if ($json) {
    $data = json_decode($json, true);
    $list = $data['blocklist'] 
         ?? $data['data'] 
         ?? (is_array($data) ? $data : []);
    
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
    
    foreach (array_slice($list, 0, 300) as $entry) {
        $ip = $entry['ip_address'] 
           ?? $entry['ip'] ?? '';
        if (!filter_var($ip, FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE)) continue;
        
        $malware = $entry['malware'] 
                ?? $entry['malware_family'] 
                ?? 'Botnet C2';
        $port    = $entry['port']       ?? '';
        $country = $entry['country']    ?? '';
        $seen    = $entry['last_online'] 
                ?? $entry['last_seen']  
                ?? date('Y-m-d H:i:s');
        
        $ts  = date('Y-m-d H:i:s', 
               strtotime($seen) ?: time());
        $ctry = $country ? " [{$country}]" : '';
        $portStr = $port ? " port {$port}" : '';
        $msg  = "ALERT Botnet C2{$ctry}: {$malware}"
              . " C2 server detected on{$portStr}";
        
        $vals = [$ip];
        if ($sevCol) $vals[] = 'CRITICAL';
        if ($catCol) $vals[] = 'RCE';
        $vals[] = $msg;
        $vals[] = $ts;
        
        try {
            $stmt->execute($vals);
            $inserted += $stmt->rowCount();
        } catch (PDOException $e) {
            if ($e->getCode() !== '23000') continue;
        }
    }
}

// Also geolocate any new IPs (max 10 per run)
$newIPs = $pdo->query("
    SELECT DISTINCT l.{$ipCol} as ip
    FROM logs l
    LEFT JOIN ip_geo g ON l.{$ipCol} = g.ip
    WHERE g.ip IS NULL
      AND l.{$ipCol} IS NOT NULL
      AND l.{$ipCol} != ''
    ORDER BY l.{$tsCol} DESC
    LIMIT 25
")->fetchAll(PDO::FETCH_COLUMN);

$geoStmt = $pdo->prepare("
    INSERT IGNORE INTO ip_geo
        (ip, country_code, country_name, 
         city, latitude, longitude)
    VALUES (?, ?, ?, ?, ?, ?)
");

$geoCount = 0;
foreach ($newIPs as $ip) {
    $geo = @json_decode(file_get_contents(
        "http://ip-api.com/json/{$ip}"
        . "?fields=status,country,countryCode,city,lat,lon"
    ), true);
    
    if (($geo['status'] ?? '') !== 'success') continue;
    
    $geoStmt->execute([
        $ip,
        $geo['countryCode'] ?? '',
        $geo['country']     ?? '',
        $geo['city']        ?? '',
        $geo['lat']         ?? 0,
        $geo['lon']         ?? 0,
    ]);
    $geoCount++;
    usleep(300000); // 300ms — stay under rate limit
}

$elapsed = round(microtime(true) - $start, 2);
$ts      = date('Y-m-d H:i:s');

echo "[{$ts}] Feodo: +{$inserted} new entries, "
   . "+{$geoCount} geolocated ({$elapsed}s)" 
   . PHP_EOL;

// Write status to a file dashboard can read
file_put_contents('/tmp/feodo_last_run.json', json_encode([
    'timestamp'  => $ts,
    'inserted'   => $inserted,
    'geolocated' => $geoCount,
    'elapsed'    => $elapsed,
    'status'     => 'ok',
]));

// Backfill ungeolocated IPs (run once, then remove)
$ungeo = $pdo->query("
    SELECT DISTINCT l.{$ipCol} as ip
    FROM logs l
    LEFT JOIN ip_geo g ON l.{$ipCol} = g.ip
    WHERE g.ip IS NULL
      AND l.{$ipCol} IS NOT NULL
      AND l.{$ipCol} != ''
      AND l.{$ipCol} != 'Unknown'
      AND l.{$ipCol} REGEXP 
          '^[0-9]{1,3}\.[0-9]{1,3}\.'
    LIMIT 100
")->fetchAll(PDO::FETCH_COLUMN);

$geoStmt = $pdo->prepare("
    INSERT IGNORE INTO ip_geo
        (ip, country_code, country_name,
         city, latitude, longitude)
    VALUES (?, ?, ?, ?, ?, ?)
");

foreach ($ungeo as $ip) {
    $geo = @json_decode(file_get_contents(
        "http://ip-api.com/json/{$ip}"
        . "?fields=status,country,countryCode,city,lat,lon"
    ), true);
    if (($geo['status'] ?? '') !== 'success') continue;
    $geoStmt->execute([
        $ip,
        $geo['countryCode'] ?? '',
        $geo['country']     ?? '',
        $geo['city']        ?? '',
        $geo['lat']         ?? 0,
        $geo['lon']         ?? 0,
    ]);
    usleep(250000); // 250ms rate limit
}
echo "[+] Backfilled " . count($ungeo) 
   . " IPs for geolocation" . PHP_EOL;
?>
