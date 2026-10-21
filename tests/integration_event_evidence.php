<?php
/** Transactional test against the explicitly enabled disposable Compose CI database. */
declare(strict_types=1);
if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') {
    fwrite(STDERR, "Refusing to run outside disposable Compose CI.\n"); exit(2);
}
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/soar/SiemSoarAlertPipeline.php';
function evidenceCheck(bool $ok, string $label): void {
    if (!$ok) throw new RuntimeException('FAIL: ' . $label);
    echo "PASS: $label\n";
}
$pdo->beginTransaction();
try {
    $pipeline = new SiemSoarAlertPipeline($pdo);
    $repo = new EventEvidenceRepository($pdo);
    $payload = [
        'source' => 'evidence-ci-' . bin2hex(random_bytes(4)), 'source_type' => 'sensor',
        'source_event_id' => 'one', 'source_ip' => '192.0.2.101', 'destination_ip' => '192.0.2.102',
        'severity' => 'HIGH', 'category' => 'SSH', 'message' => 'Evidence 100%_ <script>alert(1)</script>',
        'protocol' => 'tcp', 'destination_port' => 22,
        'event_timestamp' => gmdate('Y-m-d\TH:i:s\Z'), 'metadata' => ['host' => 'lab-01'],
    ];
    $body = json_encode($payload, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n";
    $result = $pipeline->ingest($payload, 'ci-evidence', $body);
    $row = $repo->findByLogId((int)$result['log_id']);
    evidenceCheck($row !== null && (int)$row['id'] === $result['evidence_id'], 'accepted alert has durable evidence ID');
    evidenceCheck($row['raw_payload'] === $body && hash('sha256', $body) === $row['payload_sha256'], 'exact submitted bytes and checksum retained');
    evidenceCheck($row['submitted_by'] === 'ci-evidence' && $row['source'] === $payload['source'], 'authenticated actor separate from claimed source');
    $canonical = json_decode($row['canonical_json'], true);
    evidenceCheck($canonical['destination_ip'] === '192.0.2.102' && $canonical['metadata'] === $payload['metadata'], 'destination and metadata retained');
    evidenceCheck(count($row['incidents']) === 1, 'stored evidence links back to correlated incident');
    $again = $pipeline->ingest($payload, 'ci-evidence', $body);
    evidenceCheck($again['duplicate'] === true && $repo->search(['source'=>$payload['source']])['total'] === 1, 'retry does not duplicate evidence');
    $next = $payload; $next['source_event_id'] = 'two';
    evidenceCheck(!$pipeline->ingest($next, 'ci-evidence')['duplicate'], 'distinct source event IDs are not collapsed');
    evidenceCheck($repo->search(['source'=>$payload['source'], 'q'=>'100%_'])['total'] === 2, 'wildcards are literal search text');
    evidenceCheck($repo->search(['source'=>$payload['source'], 'q'=>"' OR 1=1 --"])['total'] === 0, 'search is parameterized');
    $paged = $repo->search(['source'=>$payload['source']], 999, 1);
    evidenceCheck($paged['page'] === 2 && count($paged['rows']) === 1, 'pagination clamps to final page');
    evidenceCheck($repo->search(['source'=>$payload['source'], 'from'=>'2000-01-01', 'to'=>'2000-01-02'])['total'] === 0, 'date range constrains results');
    $badDate = false;
    try { $repo->search(['from'=>'2026-02-30']); } catch (InvalidArgumentException $e) { $badDate = true; }
    evidenceCheck($badDate, 'invalid date filter rejected');

    $sim = $payload; $sim['is_simulated'] = true;
    $simulation = $pipeline->ingest($sim, 'ci-evidence');
    evidenceCheck($simulation['correlation']['decision'] === 'SIMULATION_ONLY' && $simulation['correlation']['incident_id'] === null, 'simulation bypasses real incident correlation');
    $simRow = $repo->findByLogId($simulation['log_id']);
    evidenceCheck((int)$simRow['is_simulated'] === 1 && str_starts_with($simRow['message'], '[SIMULATED]'), 'simulation labeled in evidence and legacy views');
    evidenceCheck($repo->search(['source'=>$payload['source'], 'kind'=>'simulated'])['total'] === 1, 'simulation filter isolates test evidence');
    $denied = false;
    try { (new IncidentManager($pdo))->escalateAlertToIncident($simulation['log_id'], 'ci-evidence'); }
    catch (InvalidArgumentException $e) { $denied = true; }
    evidenceCheck($denied, 'manual escalation cannot turn simulation into real incident');
    $denied = false;
    try { (new IncidentRepository($pdo))->attachAlert($result['correlation']['incident_id'], $simulation['log_id']); }
    catch (InvalidArgumentException $e) { $denied = true; }
    evidenceCheck($denied, 'manual attachment cannot mix simulation into real case');

    $retry = $payload; $retry['source_event_id'] = 'rollback';
    $before = $repo->search(['source'=>$payload['source']])['total'];
    $failed = false;
    try { $pipeline->ingest($retry, 'ci-evidence', '{}'); } catch (InvalidArgumentException $e) { $failed = true; }
    evidenceCheck($failed && $pdo->inTransaction() && $repo->search(['source'=>$payload['source']])['total'] === $before, 'nested failure rolls back evidence without ending caller transaction');
    evidenceCheck(!$pipeline->ingest($retry, 'ci-evidence')['duplicate'], 'retry after rollback is accepted, not suppressed by memory cache');

    $noTime = $payload; unset($noTime['event_timestamp']); $noTime['source_event_id'] = 'no-time';
    $r = $pipeline->ingest($noTime, 'ci-evidence');
    evidenceCheck($repo->findByLogId($r['log_id'])['timestamp_origin'] === 'receipt_fallback', 'missing source timestamp explicitly marked as receipt fallback');
    $bad = $payload; $bad['is_simulated'] = 'false';
    evidenceCheck($pipeline->ingest($bad)['success'] === false, 'ambiguous simulation flag rejected');
    $bad = $payload; $bad['message'] = ['unexpected'];
    evidenceCheck($pipeline->ingest($bad)['success'] === false, 'structured message rejected before normalization');
    $normalizer = new AlertNormalizer();
    evidenceCheck($normalizer->normalizeTimestamp(1700000000000) === '2023-11-14 22:13:20', 'Unix milliseconds supported');
    $oldZone = date_default_timezone_get(); date_default_timezone_set('Asia/Kolkata');
    evidenceCheck($normalizer->normalizeTimestamp('2026-10-21T17:30:00+05:30') === '2026-10-21 12:00:00', 'source timezone normalized to UTC independently of PHP timezone');
    date_default_timezone_set($oldZone);
    echo "Event evidence integration passed; rolling back all fixtures.\n";
    $pdo->rollBack();
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    fwrite(STDERR, $e->getMessage() . "\n"); exit(1);
}
