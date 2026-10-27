<?php
header('Content-Type: application/json');
header('Cache-Control: no-cache, no-store');
header('X-Content-Type-Options: nosniff');

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/soar/SoarAuth.php';
$auth=SoarAuth::getContext($pdo);
if ($auth['auth_method']==='anonymous') {
    http_response_code(401); echo json_encode(['error'=>'Unauthorized']); exit;
}

// Get stats since last check
$since = is_string($_GET['since'] ?? null) ? $_GET['since'] : date('Y-m-d H:i:s',
         strtotime('-1 minute'));

// Validate since parameter
$since = date('Y-m-d H:i:s',
         strtotime($since) ?: strtotime('-1 minute'));

$newLogs = $pdo->prepare("
    SELECT COUNT(*) FROM logs
    WHERE timestamp > ?
");
$newLogs->execute([$since]);
$newCount = $newLogs->fetchColumn();

// Latest 5 new entries
$latest = $pdo->prepare("
    SELECT source_ip, severity, category,
           message, timestamp
    FROM logs
    WHERE timestamp > ?
    ORDER BY timestamp DESC
    LIMIT 5
");
$latest->execute([$since]);
$latestRows = $latest->fetchAll();

// Current totals
$totals = $pdo->query("
    SELECT
        COUNT(*) as total,
        COUNT(DISTINCT source_ip) as attackers,
        SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high
    FROM logs
")->fetch();

// Durable status; no inference from temporary files or inventory timestamps.
$lastRun=['status'=>'unknown'];
try {
    $run=$pdo->query("SELECT status, started_at AS timestamp, finished_at, processed_count AS processed,
        inserted_count AS inserted FROM feed_collection_runs WHERE provider='feodo_tracker' ORDER BY id DESC LIMIT 1")->fetch(PDO::FETCH_ASSOC);
    if ($run) { $lastRun=$run; $lastRun['status']=strtolower($run['status']); }
} catch (Throwable $e) { $lastRun=['status'=>'unavailable']; }

echo json_encode([
    'new_count'   => (int)$newCount,
    'latest'      => $latestRows,
    'totals'      => $totals,
    'last_fetch'  => $lastRun,
    'server_time' => date('Y-m-d H:i:s'),
    'checked_at'  => date('H:i:s'),
]);
