<?php
header('Content-Type: application/json');
header('Cache-Control: no-cache, no-store');
header('Access-Control-Allow-Origin: same-origin');

// Auth check
session_start();
if (empty($_SESSION['analyst'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

require_once __DIR__ . '/includes/db.php';

// Get stats since last check
$since = $_GET['since'] ?? date('Y-m-d H:i:s', 
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

// Last Feodo run status
$lastRun = @json_decode(
    file_get_contents('/tmp/feodo_last_run.json'), 
    true
) ?? ['status' => 'unknown'];

echo json_encode([
    'new_count'   => (int)$newCount,
    'latest'      => $latestRows,
    'totals'      => $totals,
    'last_fetch'  => $lastRun,
    'server_time' => date('Y-m-d H:i:s'),
    'checked_at'  => date('H:i:s'),
]);
