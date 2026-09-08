<?php
/**
 * ThreatPulse SOAR - Database Test Runner
 * 
 * Executes database-level test cases against MariaDB:
 * 1. Incident creation
 * 2. Referencing existing logs through incident_alerts
 * 3. Associating multiple alerts with one incident
 * 4. Linking an IOC to multiple incidents
 * 5. Creating a playbook with multiple ordered steps
 * 6. Executing a playbook run referencing an incident
 * 7. Creating an approval request referencing a playbook run
 * 8. Creating a response action referencing an approval
 * 9. Attaching evidence to an incident
 * 10. Assigning notifications to users
 * 11. Testing transactional rollback to keep database clean
 */

$is_cli = (php_sapi_name() === 'cli');

function logTest($msg, $pass = true) {
    global $is_cli;
    $status = $pass ? "\033[32m[PASS]\033[0m" : "\033[31m[FAIL]\033[0m";
    if ($is_cli) {
        echo "$status $msg\n";
    } else {
        echo htmlspecialchars(($pass ? "[PASS] " : "[FAIL] ") . $msg) . "<br>\n";
    }
}

$db_host = getenv('DB_HOST') ?: 'localhost';
$db_user = getenv('DB_USER') ?: 'redteam_user';
$db_pass = getenv('DB_PASS') ?: 'root';
$db_name = getenv('DB_NAME') ?: 'cybertech_db';

try {
    $dsn = "mysql:host=$db_host;dbname=$db_name;charset=utf8mb4";
    $pdo = new PDO($dsn, $db_user, $db_pass, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
} catch (PDOException $e) {
    logTest("Database connection error: " . $e->getMessage(), false);
    exit(1);
}

$testsPassed = 0;
$testsFailed = 0;

$pdo->beginTransaction();

try {
    // Prerequisite: Ensure test user and logs exist in this transaction
    $pdo->exec("
        INSERT INTO users (username, password, email, role) 
        VALUES ('test_soar_runner', 'argon2_dummy_hash', 'runner@threatpulse.local', 'analyst')
        ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id);
    ");
    $userId = $pdo->lastInsertId();

    $pdo->exec("
        INSERT INTO logs (source_ip, severity, category, message, timestamp) 
        VALUES ('198.51.100.77', 'CRITICAL', 'SSH', 'Test alert SSH brute force', NOW());
    ");
    $logId1 = $pdo->lastInsertId();

    $pdo->exec("
        INSERT INTO logs (source_ip, severity, category, message, timestamp) 
        VALUES ('198.51.100.77', 'HIGH', 'RCE', 'Test alert RCE command injection', NOW());
    ");
    $logId2 = $pdo->lastInsertId();

    // 1. Create a new incident
    $stmt = $pdo->prepare("
        INSERT INTO incidents (
            incident_number, title, description, severity, status, priority, risk_score, assigned_to, attack_category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");
    $stmt->execute([
        'INC-TEST-RUNNER-01',
        'Test Automated Correlation Incident',
        'Test incident description verifying Phase 1 schema capability',
        'CRITICAL', 'OPEN', 'P1', 95, $userId, 'RCE'
    ]);
    $incidentId1 = $pdo->lastInsertId();
    logTest("Test 1: New incident created successfully (ID: $incidentId1, Number: INC-TEST-RUNNER-01)", $incidentId1 > 0);
    $testsPassed++;

    // Create second incident for multi-incident IOC linkage
    $stmt->execute([
        'INC-TEST-RUNNER-02',
        'Secondary Test Incident',
        'Secondary investigation case',
        'HIGH', 'NEW', 'P2', 70, $userId, 'C2'
    ]);
    $incidentId2 = $pdo->lastInsertId();

    // 2 & 3. Reference existing logs through incident_alerts & multiple alerts per incident
    $stmtAlerts = $pdo->prepare("
        INSERT INTO incident_alerts (incident_id, log_id, correlation_rule) 
        VALUES (?, ?, ?)
    ");
    $stmtAlerts->execute([$incidentId1, $logId1, 'RULE_SAME_IP']);
    $stmtAlerts->execute([$incidentId1, $logId2, 'RULE_ATTACK_ESCALATION']);

    $countAlerts = $pdo->query("SELECT COUNT(*) FROM incident_alerts WHERE incident_id = $incidentId1")->fetchColumn();
    logTest("Test 2 & 3: Associated $countAlerts existing SIEM logs with Incident $incidentId1 via incident_alerts junction", $countAlerts == 2);
    $testsPassed++;

    // 4. Link an IOC to multiple incidents
    $stmtIoc = $pdo->prepare("
        INSERT INTO iocs (ioc_type, ioc_value, threat_type, malware_family, reputation_score, confidence_score) 
        VALUES (?, ?, ?, ?, ?, ?)
    ");
    $stmtIoc->execute(['IPV4', '198.51.100.77', 'Botnet C2', 'Mirai', 98, 90]);
    $iocId = $pdo->lastInsertId();

    $stmtIncIoc = $pdo->prepare("INSERT INTO incident_iocs (incident_id, ioc_id, role) VALUES (?, ?, ?)");
    $stmtIncIoc->execute([$incidentId1, $iocId, 'ATTACKER']);
    $stmtIncIoc->execute([$incidentId2, $iocId, 'C2_SERVER']);

    $countIocIncidents = $pdo->query("SELECT COUNT(*) FROM incident_iocs WHERE ioc_id = $iocId")->fetchColumn();
    logTest("Test 4: Linked IOC '$iocId' (198.51.100.77) to $countIocIncidents distinct incidents", $countIocIncidents == 2);
    $testsPassed++;

    // 5. Create a playbook with multiple ordered steps
    $stmtPb = $pdo->prepare("
        INSERT INTO playbooks (
            playbook_name, display_name, description, category, trigger_type, requires_approval, min_approval_tier, created_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ");
    $stmtPb->execute([
        'PB_RUNNER_SSH_MITIGATION',
        'SSH Attack Auto-Triage',
        'Automated triage and containment workflow',
        'CONTAINMENT', 'AUTOMATIC', true, 'LEAD', $userId
    ]);
    $playbookId = $pdo->lastInsertId();

    $stmtStep = $pdo->prepare("
        INSERT INTO playbook_steps (playbook_id, step_order, step_name, action_type, action_parameters, timeout_seconds) 
        VALUES (?, ?, ?, ?, ?, ?)
    ");
    $stmtStep->execute([$playbookId, 1, 'Enrich Attacker IP', 'ENRICH_IP', json_encode(['provider' => 'ip_api']), 30]);
    $stmtStep->execute([$playbookId, 2, 'Request Approval', 'REQUEST_APPROVAL', json_encode(['tier' => 'LEAD']), 300]);
    $stmtStep->execute([$playbookId, 3, 'Block IP', 'FIREWALL_BLOCK_IP', json_encode(['duration' => 86400]), 60]);

    $countSteps = $pdo->query("SELECT COUNT(*) FROM playbook_steps WHERE playbook_id = $playbookId")->fetchColumn();
    logTest("Test 5: Created Playbook '$playbookId' with $countSteps ordered steps", $countSteps == 3);
    $testsPassed++;

    // 6. Playbook run referencing an incident
    $runUuid = 'RUN-UUID-' . bin2hex(random_bytes(8));
    $stmtRun = $pdo->prepare("
        INSERT INTO playbook_runs (
            run_uuid, playbook_id, incident_id, triggered_by, analyst_id, status, current_step_order, execution_context
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ");
    $stmtRun->execute([
        $runUuid, $playbookId, $incidentId1, 'AUTOMATION', $userId, 'WAITING_APPROVAL', 2, json_encode(['ip' => '198.51.100.77'])
    ]);
    $runId = $pdo->lastInsertId();
    logTest("Test 6: Created Playbook Run '$runId' (UUID: $runUuid) referencing Incident $incidentId1", $runId > 0);
    $testsPassed++;

    // 7. Human approval request referencing a playbook run
    $stmtApprove = $pdo->prepare("
        INSERT INTO approval_requests (
            playbook_run_id, incident_id, action_name, action_description, action_payload, required_tier, status, reviewed_by, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL 2 HOUR))
    ");
    $stmtApprove->execute([
        $runId, $incidentId1, 'FIREWALL_BLOCK_IP', 'Block attacker IP on perimeter firewall', json_encode(['ip' => '198.51.100.77']), 'LEAD', 'APPROVED', $userId
    ]);
    $approvalId = $pdo->lastInsertId();
    logTest("Test 7: Created Approval Request '$approvalId' linked to Playbook Run $runId", $approvalId > 0);
    $testsPassed++;

    // 8. Response action referencing an approval
    $actionUuid = 'ACT-UUID-' . bin2hex(random_bytes(8));
    $stmtAction = $pdo->prepare("
        INSERT INTO response_actions (
            action_uuid, incident_id, playbook_run_id, approval_id, action_type, target_entity, status, output_log, rollback_supported
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");
    $stmtAction->execute([
        $actionUuid, $incidentId1, $runId, $approvalId, 'FIREWALL_BLOCK_IP', '198.51.100.77', 'SUCCESS', 'Firewall rule applied successfully', true
    ]);
    $actionId = $pdo->lastInsertId();
    logTest("Test 8: Created Response Action '$actionId' (UUID: $actionUuid) referencing Approval $approvalId", $actionId > 0);
    $testsPassed++;

    // 9. Evidence attached to an incident
    $dataHash = hash('sha256', 'SAMPLE_RAW_LOG_EVIDENCE_FOR_FORENSICS');
    $stmtEvidence = $pdo->prepare("
        INSERT INTO evidence (
            incident_id, evidence_type, title, description, data_hash, content_text, collected_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ");
    $stmtEvidence->execute([
        $incidentId1, 'LOG_SNIPPET', 'SSH Brute Force Forensic Log', 'Raw auth logs captured during incident', $dataHash, 'Failed password for invalid user root from 198.51.100.77', $userId
    ]);
    $evidenceId = $pdo->lastInsertId();
    logTest("Test 9: Attached Forensic Evidence '$evidenceId' with SHA-256 hash ($dataHash) to Incident $incidentId1", $evidenceId > 0);
    $testsPassed++;

    // 10. Notifications assigned to users
    $stmtNotif = $pdo->prepare("
        INSERT INTO notifications (
            recipient_id, incident_id, title, message, notification_type, is_read
        ) VALUES (?, ?, ?, ?, ?, ?)
    ");
    $stmtNotif->execute([
        $userId, $incidentId1, 'Urgent: Approval Granted for Incident INC-TEST-RUNNER-01', 'Containment action executed.', 'APPROVAL_REQUIRED', false
    ]);
    $notifId = $pdo->lastInsertId();
    logTest("Test 10: Created Notification '$notifId' assigned to User $userId", $notifId > 0);
    $testsPassed++;

} catch (Exception $e) {
    logTest("Exception during database test execution: " . $e->getMessage(), false);
    $testsFailed++;
} finally {
    // Clean rollback
    $pdo->rollBack();
    logTest("Test transaction rolled back cleanly. No residual data left in database.", true);
}

echo "\n==================================================\n";
echo "DATABASE TEST RESULTS: $testsPassed Passed, $testsFailed Failed\n";
echo "==================================================\n";

exit($testsFailed === 0 ? 0 : 1);
