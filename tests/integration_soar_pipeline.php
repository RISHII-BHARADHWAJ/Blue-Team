<?php
/**
 * Disposable MariaDB integration smoke test: legacy SIEM alert -> SOAR incident
 * -> playbook DRY_RUN. Run only against the isolated Docker Compose CI database.
 *
 * All test inserts occur inside one transaction and are rolled back.
 * No containment, notification, or other live response action is executed.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' || getenv('SOAR_INTEGRATION_TEST') !== '1' || getenv('DB_HOST') !== 'db') {
    fwrite(STDERR, "Refusing to run outside the explicitly enabled disposable Compose CI environment.\n");
    exit(2);
}

require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/soar/AlertIngestionService.php';
require_once __DIR__ . '/../includes/soar/IncidentManager.php';
require_once __DIR__ . '/../includes/soar/SiemSoarAlertPipeline.php';
require_once __DIR__ . '/../includes/soar/playbooks/PlaybookEngine.php';
require_once __DIR__ . '/../includes/soar/playbooks/PlaybookRepository.php';

function checkIntegration(bool $condition, string $description): void {
    if (!$condition) {
        throw new RuntimeException('FAIL: ' . $description);
    }
    echo "PASS: {$description}\n";
}

$pdo->beginTransaction();
try {
    $sourceIp = '198.51.100.' . random_int(1, 254);
    $message = 'CI integration smoke event ' . bin2hex(random_bytes(8));

    $logStmt = $pdo->prepare(
        "INSERT INTO logs (source_ip, severity, category, message, timestamp) VALUES (?, 'HIGH', 'SSH', ?, NOW())"
    );
    $logStmt->execute([$sourceIp, $message]);
    $logId = (int) $pdo->lastInsertId();
    $rowStmt = $pdo->prepare('SELECT * FROM logs WHERE id = ?');
    $rowStmt->execute([$logId]);
    $log = $rowStmt->fetch();
    checkIntegration(is_array($log), 'legacy SIEM log persisted');

    $ingestion = new AlertIngestionService($pdo);
    $accepted = $ingestion->ingestLegacyLog($log, 'ci-integration');
    checkIntegration(
        ($accepted['success'] ?? false) === true && ($accepted['status'] ?? '') === 'accepted',
        'legacy log accepted and normalized'
    );
    $duplicate = $ingestion->ingestLegacyLog($log, 'ci-integration');
    checkIntegration(($duplicate['duplicate'] ?? false) === true, 'duplicate log suppressed');

    $manager = new IncidentManager($pdo);
    $processed = $manager->processAlert($accepted['alert'], $logId, 'ci-integration');
    checkIntegration(($processed['decision'] ?? '') === 'CREATE', 'high-severity alert creates incident');
    $incident = $processed['incident'] ?? [];
    $incidentId = (int) ($incident['id'] ?? 0);
    checkIntegration($incidentId > 0 && ($incident['severity'] ?? '') === 'HIGH', 'incident saved with severity');
    checkIntegration(
        count($incident['alerts'] ?? []) === 1 && (int) $incident['alerts'][0]['log_id'] === $logId,
        'incident linked to original SIEM log'
    );
    checkIntegration(count($incident['timeline'] ?? []) >= 2, 'incident timeline persisted');

    // Only a benign context-collection step is defined. DRY_RUN prevents handler side effects.
    $playbookName = 'ci-smoke-' . bin2hex(random_bytes(8));
    $pbStmt = $pdo->prepare(
        "INSERT INTO playbooks (playbook_name, display_name, category, trigger_type, requires_approval, is_active)
         VALUES (?, 'CI smoke: context only', 'INVESTIGATION', 'MANUAL', 0, 1)"
    );
    $pbStmt->execute([$playbookName]);
    $playbookId = (int) $pdo->lastInsertId();
    $repo = new PlaybookRepository($pdo);
    $stepId = $repo->createStep($playbookId, [
        'step_order' => 1,
        'step_name' => 'Preview incident context',
        'action_type' => 'COLLECT_INCIDENT_CONTEXT',
        'action_parameters' => [],
    ]);
    checkIntegration($stepId > 0, 'safe playbook definition saved');

    $engine = new PlaybookEngine($pdo);
    $run = $engine->startRun($playbookId, $incidentId, 'DRY_RUN', ['username' => 'ci-integration']);
    checkIntegration(($run['status'] ?? '') === 'COMPLETED', 'dry-run playbook completed');
    $resultsStmt = $pdo->prepare(
        'SELECT status, is_dry_run FROM playbook_step_results WHERE playbook_run_id = ?'
    );
    $resultsStmt->execute([(int) $run['id']]);
    $results = $resultsStmt->fetchAll();
    checkIntegration(
        count($results) === 1 && $results[0]['status'] === 'SUCCESS' && (int) $results[0]['is_dry_run'] === 1,
        'step result persisted and explicitly marked dry-run'
    );

    // Exercise the exact service used by HTTP sensors: durable event -> correlation.
    $pipeline = new SiemSoarAlertPipeline($pdo);
    $sensorEvent = [
        'source' => 'ci_sensor',
        'source_type' => 'log',
        'source_event_id' => bin2hex(random_bytes(8)),
        'source_ip' => '203.0.113.55',
        'severity' => 'HIGH',
        'category' => 'SSH',
        'message' => 'Sensor event ' . bin2hex(random_bytes(8)),
        'event_timestamp' => date('Y-m-d H:i:s'),
    ];
    $sensorResult = $pipeline->ingest($sensorEvent, 'ci-sensor');
    checkIntegration(
        ($sensorResult['status'] ?? '') === 'accepted' && (int)($sensorResult['log_id'] ?? 0) > 0,
        'sensor event durably assigned a SIEM log ID'
    );
    checkIntegration(
        ($sensorResult['correlation']['decision'] ?? '') === 'CREATE'
            && (int)($sensorResult['correlation']['incident_id'] ?? 0) > 0,
        'accepted HTTP sensor event reaches incident correlation'
    );
    $sensorDuplicate = $pipeline->ingest($sensorEvent, 'ci-sensor');
    checkIntegration(
        ($sensorDuplicate['duplicate'] ?? false) === true
            && !isset($sensorDuplicate['log_id']),
        'duplicate sensor event does not create a second SIEM log'
    );

    $mediumEvent = $sensorEvent;
    $mediumEvent['source_ip'] = '203.0.113.56';
    $mediumEvent['severity'] = 'MEDIUM';
    $mediumEvent['message'] = 'Medium severity event ' . bin2hex(random_bytes(8));
    $mediumResult = $pipeline->ingest($mediumEvent, 'ci-sensor');
    $severityStmt = $pdo->prepare('SELECT severity FROM logs WHERE id = ?');
    $severityStmt->execute([(int)$mediumResult['log_id']]);
    checkIntegration(
        $severityStmt->fetchColumn() === 'WARNING',
        'canonical MEDIUM severity maps to legacy SIEM WARNING without rejection'
    );

    echo "Integration smoke checks passed. Rolling back test data.\n";
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    exit(1);
}
if ($pdo->inTransaction()) {
    $pdo->rollBack();
}
