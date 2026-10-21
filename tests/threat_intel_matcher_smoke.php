<?php
/** Lightweight read-only test for threat intelligence source-IP attribution. */
declare(strict_types=1);
require_once __DIR__ . '/../includes/soar/ThreatIntelMatcher.php';
if (!extension_loaded('pdo_sqlite')) {
    echo "SKIP: pdo_sqlite unavailable\n";
    exit(0);
}
$db = new PDO('sqlite::memory:');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
// SQLite cannot emulate MariaDB information_schema; test input validation only.
$matcher = new ThreatIntelMatcher($db);
foreach ([null, '', 'not-an-ip'] as $invalid) {
    if ($matcher->matchSourceIp($invalid) !== []) {
        throw new RuntimeException('Invalid source IP must never match.');
    }
}
echo "PASS: invalid IPs do not match external intelligence\n";
