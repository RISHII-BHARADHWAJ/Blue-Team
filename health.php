<?php
// Minimal liveness/readiness probe: no session, login throttling, or diagnostic details.
header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
try {
    $pdo = new PDO('mysql:host='.(getenv('DB_HOST') ?: 'localhost').';dbname='.(getenv('DB_NAME') ?: 'cybertech_db').';charset=utf8mb4', getenv('DB_USER') ?: 'redteam_user', getenv('DB_PASS') ?: 'root', [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $pdo->query('SELECT 1 FROM users LIMIT 1');
    echo '{"status":"ok"}';
} catch (Throwable $e) {
    http_response_code(503);
    echo '{"status":"unavailable"}';
}
