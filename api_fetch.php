<?php
/**
 * External IP-reputation feed collector.
 * These listings are intelligence, NOT observed attacks against ThreatPulse.
 * Feodo is handled separately by feodo_realtime.php.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(405);
    exit('CLI ingestion only.');
}

require_once __DIR__ . '/includes/db.php';

$lockHandle = fopen('/tmp/threatpulse_bulk_fetch.lock', 'c');
if ($lockHandle === false || !flock($lockHandle, LOCK_EX | LOCK_NB)) {
    echo "[ThreatIntel] Another fetch is already running.\n";
    exit(0);
}
register_shutdown_function(static function () use ($lockHandle): void {
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
});

$started = microtime(true);
$feeds = [
    'emerging_threats' => 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    'cins_army' => 'https://cinsscore.com/list/ci-badguys.txt',
    'blocklist_de' => 'https://lists.blocklist.de/lists/all.txt',
];
$results = [];
$failures = 0;
$newTotal = 0;

try {
    $exists = $pdo->query("SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'threat_feed_indicators'")->fetchColumn();
    if ((int)$exists !== 1) {
        throw new RuntimeException('Missing threat_feed_indicators table; apply migration 007.');
    }

    $upsert = $pdo->prepare("INSERT INTO threat_feed_indicators
        (provider, indicator_type, indicator_value, threat_type, fetched_at)
        VALUES (?, ?, ?, 'reported_malicious_ip', UTC_TIMESTAMP())
        ON DUPLICATE KEY UPDATE fetched_at = UTC_TIMESTAMP()");

    foreach ($feeds as $provider => $url) {
        $new = 0;
        $valid = 0;
        try {
            $context = stream_context_create(['http' => [
                'timeout' => 25,
                'user_agent' => 'ThreatPulse-BlueTeam/1.0',
                'ignore_errors' => false,
            ]]);
            $raw = @file_get_contents($url, false, $context);
            if ($raw === false || strlen($raw) > 10 * 1024 * 1024) {
                throw new RuntimeException('Feed unavailable or exceeds size limit.');
            }
            // Each feed is a plaintext IP blocklist. Never invent a timestamp,
            // malware family, severity, or attack category for these IPs.
            foreach (explode("\n", $raw) as $line) {
                $ip = trim($line);
                if ($ip === '' || $ip[0] === '#' || strlen($ip) > 45) continue;
                if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) continue;
                $type = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'IPV4' : 'IPV6';
                $upsert->execute([$provider, $type, $ip]);
                $new += $upsert->rowCount() === 1 ? 1 : 0;
                $valid++;
                if ($valid >= 2000) break;
            }
            if ($valid === 0) throw new RuntimeException('Feed returned no usable IP addresses.');
            $newTotal += $new;
            $results[$provider] = ['status' => 'ok', 'processed' => $valid, 'inserted' => $new];
            echo "[ThreatIntel] {$provider}: {$valid} processed, {$new} new.\n";
        } catch (Throwable $e) {
            $failures++;
            $results[$provider] = ['status' => 'error', 'processed' => $valid, 'inserted' => $new];
            error_log("[ThreatIntel] {$provider}: " . $e->getMessage());
            echo "[ThreatIntel] {$provider}: unavailable (see logs).\n";
        }
    }
} catch (Throwable $e) {
    $failures = count($feeds);
    error_log('[ThreatIntel] ' . $e->getMessage());
    echo "[ThreatIntel] Setup error: " . $e->getMessage() . "\n";
}

// ThreatFox requires an Auth-Key. It is deliberately not queried without
// explicit configuration; a keyless request would silently fail.
if (!getenv('THREATFOX_AUTH_KEY')) {
    $results['threatfox'] = ['status' => 'not_configured'];
}

$status = $failures === 0 ? 'ok' : ($failures === count($feeds) ? 'error' : 'partial');
$result = [
    'timestamp' => gmdate('Y-m-d H:i:s'),
    'status' => $status,
    'new_indicators' => $newTotal,
    'feeds' => $results,
    'elapsed' => round(microtime(true) - $started, 2),
];

$statusDir = '/run/threatpulse';
if (is_dir($statusDir) && is_writable($statusDir)) {
    $tmp = tempnam($statusDir, '.bulk-');
    if ($tmp !== false) {
        file_put_contents($tmp, json_encode($result, JSON_UNESCAPED_SLASHES));
        chmod($tmp, 0640);
        rename($tmp, $statusDir . '/bulk_last_run.json');
    }
}
echo "[ThreatIntel] {$status}: {$newTotal} new indicators; no SIEM attack events created.\n";
exit($status === 'error' ? 1 : 0);
