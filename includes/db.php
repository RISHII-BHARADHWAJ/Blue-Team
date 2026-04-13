<?php
$db_host = getenv('DB_HOST') ?: 'localhost';
try {
    $pdo = new PDO(
        "mysql:host={$db_host};dbname=cybertech_db;charset=utf8mb4",
        'redteam_user',
        'root',
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
} catch (PDOException $e) {
    error_log('DB connection failed: ' . $e->getMessage());
    die(json_encode(['error' => 'Database unavailable']));
}
