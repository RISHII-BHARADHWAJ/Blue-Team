<?php
/**
 * Feodo Tracker ingestion: external intelligence inventory, not SIEM detections.
 * This script is intentionally CLI-only and never writes imported IPs to logs.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(405);
    header('Allow: POST');
    exit('CLI ingestion only.');
}

require_once __DIR__ . '/includes/db.php';

$lock = '/tmp/feodo_realtime.lock';
if (is_file($lock) && time() - (int)filemtime($lock) < 240) {
    echo "[Feodo] Another fetch is in progress.\n";
    exit(0);
}
file_put_contents($lock, (string)getmypid());
register_shutdown_function(static function () use ($lock): void { @unlink($lock); });

$started = microtime(true);
$timestamp = gmdate('Y-m-d H:i:s');
$status = 'error';
$inserted = 0;
$processed = 0;
$message = '';

try {
    $exists = $pdo->query("SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'threat_feed_indicators'")->fetchColumn();
    if ((int)$exists !== 1) {
        throw new RuntimeException('Missing threat_feed_indicators table. Apply migration 007 first.');
    }

    $ctx = stream_context_create(['http' => [
        'timeout' => 20,
        'user_agent' => 'ThreatPulse-BlueTeam/1.0',
        'ignore_errors' => false,
    ]]);
    $raw = @file_get_contents('https://feodotracker.abuse.ch/downloads/ipblocklist.json', false, $ctx);
    if ($raw === false) {
        throw new RuntimeException('Feodo Tracker feed unavailable.');
    }
    $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    $entries = $data['blocklist'] ?? $data['data'] ?? $data;
    if (!is_array($entries) || !array_is_list($entries)) {
        throw new RuntimeException('Unexpected Feodo JSON structure.');
    }

    $stmt = $pdo->prepare("INSERT INTO threat_feed_indicators
        (provider, indicator_type, indicator_value, threat_type, malware_family,
         port, source_first_seen, source_last_seen, fetched_at)
        VALUES ('feodo_tracker', ?, ?, 'botnet_c2', ?, ?, ?, ?, UTC_TIMESTAMP())
        ON DUPLICATE KEY UPDATE
            threat_type = VALUES(threat_type),
            malware_family = VALUES(malware_family),
            port = VALUES(port),
            source_first_seen = COALESCE(VALUES(source_first_seen), source_first_seen),
            source_last_seen = COALESCE(VALUES(source_last_seen), source_last_seen),
            fetched_at = UTC_TIMESTAMP()");

    foreach (array_slice($entries, 0, 300) as $entry) {
        if (!is_array($entry)) continue;
        $ip = (string)($entry['ip_address'] ?? $entry['ip'] ?? '');
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) continue;
        $type = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'IPV4' : 'IPV6';
        $malware = substr((string)($entry['malware'] ?? $entry['malware_family'] ?? 'Unknown'), 0, 150);
        $port = filter_var($entry['port'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 65535]]);
        $first = $entry['first_seen'] ?? null;
        $last = $entry['last_online'] ?? $entry['last_seen'] ?? null;
        $firstTs = is_string($first) && strtotime($first) !== false ? gmdate('Y-m-d H:i:s', strtotime($first)) : null;
        $lastTs = is_string($last) && strtotime($last) !== false ? gmdate('Y-m-d H:i:s', strtotime($last)) : null;

        $stmt->execute([$type, $ip, $malware, $port === false ? null : $port, $firstTs, $lastTs]);
        $inserted += $stmt->rowCount() === 1 ? 1 : 0;
        $processed++;
    }
    $status = 'ok';
    $message = "Processed {$processed} Feodo indicators; {$inserted} newly inventoried.";
} catch (Throwable $e) {
    $message = $e->getMessage();
    error_log('[Feodo] ' . $message);
}

$result = [
    'timestamp' => $timestamp,
    'status' => $status,
    'processed' => $processed,
    'inserted' => $inserted,
    'elapsed' => round(microtime(true) - $started, 2),
];
$statusDir = '/run/threatpulse';
if (is_dir($statusDir) && is_writable($statusDir)) {
    $tmp = tempnam($statusDir, '.feodo-');
    if ($tmp !== false) {
        file_put_contents($tmp, json_encode($result, JSON_UNESCAPED_SLASHES));
        chmod($tmp, 0640);
        rename($tmp, $statusDir . '/feodo_last_run.json');
    }
}
echo "[{$timestamp}] Feodo: {$message}\n";
exit($status === 'ok' ? 0 : 1);
