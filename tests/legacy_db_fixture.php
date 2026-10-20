<?php
/**
 * Real database fixtures for Phase 3/4 tests.
 *
 * Intentionally restricted to the ephemeral Docker Compose CI environment.
 * Every test process owns a transaction that is rolled back at shutdown.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' || getenv('SOAR_LEGACY_DB_TEST') !== '1' || getenv('DB_HOST') !== 'db') {
    fwrite(STDERR, "DB-backed legacy tests require disposable Compose CI (SOAR_LEGACY_DB_TEST=1).\n");
    exit(2);
}

require_once __DIR__ . '/../includes/db.php';
$pdo->beginTransaction();
register_shutdown_function(static function () use ($pdo): void {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
});

/** Insert a disposable SIEM log with an authentic FK target. */
function createFixtureLog(string $severity = 'HIGH', string $category = 'SSH'): int {
    $stmt = $GLOBALS['pdo']->prepare(
        'INSERT INTO logs (source_ip, severity, category, message, timestamp) VALUES (?, ?, ?, ?, NOW())'
    );
    $stmt->execute([
        '198.51.100.83',
        $severity,
        $category,
        'Legacy fixture ' . bin2hex(random_bytes(6)),
    ]);
    return (int) $GLOBALS['pdo']->lastInsertId();
}
