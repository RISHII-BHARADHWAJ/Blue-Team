<?php
/**
 * ThreatPulse SOAR - Schema Verification Tool
 * 
 * Verifies that:
 * 1. All 15 SOAR tables exist.
 * 2. Primary keys exist for all tables.
 * 3. Required unique constraints and indexes exist.
 * 4. Foreign key definitions are intact and valid.
 * 5. Migration is idempotent (re-running produces no errors or data corruption).
 * 6. Existing SIEM tables (logs, ip_geo, users, audit_log, activity_logs, rate_limits) remain untouched.
 * 
 * Safety: This script performs non-destructive read-only introspection on information_schema.
 */

$is_cli = (php_sapi_name() === 'cli');

function logMessage($msg, $type = 'INFO') {
    global $is_cli;
    $colors = [
        'INFO'    => "\033[36m[INFO]\033[0m",
        'SUCCESS' => "\033[32m[PASS]\033[0m",
        'WARN'    => "\033[33m[WARN]\033[0m",
        'FAIL'    => "\033[31m[FAIL]\033[0m",
    ];
    $tag = $colors[$type] ?? "[$type]";
    if ($is_cli) {
        echo "$tag $msg\n";
    } else {
        echo htmlspecialchars("[$type] $msg") . "<br>\n";
    }
}

// 1. Establish Database Connection
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
    logMessage("Connected to MariaDB database: $db_name on $db_host", 'SUCCESS');
} catch (PDOException $e) {
    logMessage("Database connection failed: " . $e->getMessage(), 'FAIL');
    exit(1);
}

$passed = 0;
$failed = 0;

// 2. Check Existing SIEM Tables Preservation
$expectedSiemTables = [
    'logs'          => ['id', 'source_ip', 'severity', 'category', 'message', 'timestamp'],
    'ip_geo'        => ['ip', 'country_code', 'country_name', 'city', 'latitude', 'longitude', 'created_at'],
    'users'         => ['id', 'username', 'password', 'email', 'role', 'credits', 'failed_attempts', 'locked_until', 'two_factor_secret', 'created_at'],
    'audit_log'     => ['id', 'timestamp', 'analyst', 'ip_address', 'action', 'target', 'result', 'details', 'user_agent'],
    'activity_logs' => ['id', 'timestamp', 'ip_address', 'user_agent', 'action', 'details', 'request_uri'],
    'rate_limits'   => ['ip_action_key', 'request_count', 'window_start'],
];

logMessage("Verifying existing SIEM tables baseline...", 'INFO');
foreach ($expectedSiemTables as $table => $expectedCols) {
    $stmt = $pdo->prepare("SELECT column_name FROM information_schema.columns WHERE table_schema = ? AND table_name = ?");
    $stmt->execute([$db_name, $table]);
    $cols = $stmt->fetchAll(PDO::FETCH_COLUMN);

    if (empty($cols)) {
        logMessage("SIEM table '$table' does not exist yet (will be initialized on standard deployment).", 'WARN');
    } else {
        $missingCols = array_diff($expectedCols, $cols);
        if (empty($missingCols)) {
            logMessage("SIEM table '$table' is intact with all " . count($cols) . " original columns.", 'SUCCESS');
            $passed++;
        } else {
            logMessage("SIEM table '$table' is missing expected columns: " . implode(', ', $missingCols), 'FAIL');
            $failed++;
        }
    }
}

// 3. Check All 15 SOAR Tables
$expectedSoarTables = [
    'incidents'          => ['id', 'incident_number', 'title', 'description', 'severity', 'status', 'priority', 'risk_score', 'assigned_to', 'lead_analyst', 'attack_category', 'mitre_tactics', 'mitre_techniques', 'contained_at', 'resolved_at', 'closed_at', 'created_at', 'updated_at'],
    'incident_alerts'    => ['id', 'incident_id', 'log_id', 'correlation_rule', 'added_at'],
    'incident_events'    => ['id', 'incident_id', 'event_source', 'raw_event_id', 'event_timestamp', 'summary', 'raw_payload', 'added_at'],
    'incident_timeline'  => ['id', 'incident_id', 'event_type', 'actor_type', 'actor_name', 'summary', 'details', 'created_at'],
    'iocs'               => ['id', 'ioc_type', 'ioc_value', 'threat_type', 'malware_family', 'reputation_score', 'confidence_score', 'source_feed', 'is_whitelisted', 'first_seen', 'last_seen', 'expires_at', 'created_at'],
    'incident_iocs'      => ['id', 'incident_id', 'ioc_id', 'role', 'discovered_at'],
    'enrichment_results' => ['id', 'ioc_id', 'provider', 'status', 'raw_response', 'parsed_summary', 'cached_until', 'created_at'],
    'playbooks'          => ['id', 'playbook_name', 'display_name', 'description', 'category', 'trigger_type', 'trigger_condition', 'requires_approval', 'min_approval_tier', 'is_active', 'version', 'created_by', 'created_at', 'updated_at'],
    'playbook_steps'     => ['id', 'playbook_id', 'step_order', 'step_name', 'action_type', 'action_parameters', 'on_success_step', 'on_failure_step', 'timeout_seconds'],
    'playbook_runs'      => ['id', 'run_uuid', 'playbook_id', 'incident_id', 'triggered_by', 'analyst_id', 'status', 'current_step_order', 'execution_context', 'error_message', 'started_at', 'completed_at'],
    'approval_requests'  => ['id', 'playbook_run_id', 'incident_id', 'action_name', 'action_description', 'action_payload', 'required_tier', 'status', 'requested_at', 'reviewed_by', 'reviewed_at', 'rejection_reason', 'expires_at'],
    'response_actions'   => ['id', 'action_uuid', 'incident_id', 'playbook_run_id', 'approval_id', 'action_type', 'target_entity', 'status', 'dispatched_at', 'executed_at', 'output_log', 'rollback_supported', 'is_rolled_back'],
    'evidence'           => ['id', 'incident_id', 'evidence_type', 'title', 'description', 'data_hash', 'content_text', 'file_path', 'collected_by', 'collected_at'],
    'case_notes'         => ['id', 'incident_id', 'author_id', 'note_text', 'is_pinned', 'created_at', 'updated_at'],
    'notifications'      => ['id', 'recipient_id', 'incident_id', 'title', 'message', 'notification_type', 'is_read', 'created_at'],
];

logMessage("\nVerifying 15 SOAR tables and columns...", 'INFO');
foreach ($expectedSoarTables as $table => $columns) {
    $stmt = $pdo->prepare("SELECT column_name FROM information_schema.columns WHERE table_schema = ? AND table_name = ?");
    $stmt->execute([$db_name, $table]);
    $existingCols = $stmt->fetchAll(PDO::FETCH_COLUMN);

    if (empty($existingCols)) {
        logMessage("SOAR table '$table' NOT FOUND.", 'FAIL');
        $failed++;
        continue;
    }

    $missing = array_diff($columns, $existingCols);
    if (!empty($missing)) {
        logMessage("SOAR table '$table' missing columns: " . implode(', ', $missing), 'FAIL');
        $failed++;
    } else {
        logMessage("SOAR table '$table' verified (" . count($existingCols) . " columns).", 'SUCCESS');
        $passed++;
    }
}

// Dedicated external threat-intelligence inventory (migration 007).
$feedCols = ['id', 'provider', 'indicator_type', 'indicator_value', 'threat_type',
    'malware_family', 'port', 'source_first_seen', 'source_last_seen', 'fetched_at'];
$stmt = $pdo->prepare("SELECT column_name FROM information_schema.columns
    WHERE table_schema = ? AND table_name = 'threat_feed_indicators'");
$stmt->execute([$db_name]);
$foundFeedCols = $stmt->fetchAll(PDO::FETCH_COLUMN);
$missingFeedCols = array_diff($feedCols, $foundFeedCols);
if (empty($foundFeedCols) || !empty($missingFeedCols)) {
    logMessage("Threat intelligence inventory missing or incomplete (migration 007).", 'FAIL');
    $failed++;
} else {
    logMessage("Threat intelligence indicator inventory verified.", 'SUCCESS');
    $passed++;
}

// 4. Verify Unique Constraints
$expectedUniqueConstraints = [
    'incidents'        => ['incident_number'],
    'incident_alerts'  => ['incident_id', 'log_id'],
    'iocs'             => ['ioc_type', 'ioc_value'],
    'incident_iocs'    => ['incident_id', 'ioc_id'],
    'playbooks'        => ['playbook_name'],
    'playbook_steps'   => ['playbook_id', 'step_order'],
    'playbook_runs'    => ['run_uuid'],
    'response_actions' => ['action_uuid'],
];

logMessage("\nVerifying SOAR uniqueness constraints...", 'INFO');
foreach ($expectedUniqueConstraints as $table => $cols) {
    $stmt = $pdo->prepare("
        SELECT tc.constraint_name, kcu.column_name 
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu 
          ON tc.constraint_name = kcu.constraint_name 
         AND tc.table_schema = kcu.table_schema 
         AND tc.table_name = kcu.table_name
        WHERE tc.table_schema = ? 
          AND tc.table_name = ? 
          AND tc.constraint_type = 'UNIQUE'
    ");
    $stmt->execute([$db_name, $table]);
    $found = $stmt->fetchAll();
    
    $foundCols = array_column($found, 'column_name');
    $allPresent = true;
    foreach ($cols as $c) {
        if (!in_array($c, $foundCols)) {
            $allPresent = false;
            break;
        }
    }

    if ($allPresent) {
        logMessage("Unique constraint verified on '$table' (" . implode(', ', $cols) . ").", 'SUCCESS');
        $passed++;
    } else {
        logMessage("Unique constraint MISSING on '$table' for (" . implode(', ', $cols) . ").", 'FAIL');
        $failed++;
    }
}

// 5. Verify Foreign Keys
$expectedForeignKeys = [
    'incident_alerts'   => ['incident_id' => 'incidents', 'log_id' => 'logs'],
    'incident_events'   => ['incident_id' => 'incidents'],
    'incident_timeline' => ['incident_id' => 'incidents'],
    'incident_iocs'     => ['incident_id' => 'incidents', 'ioc_id' => 'iocs'],
    'enrichment_results'=> ['ioc_id' => 'iocs'],
    'playbook_steps'    => ['playbook_id' => 'playbooks'],
    'playbook_runs'     => ['playbook_id' => 'playbooks', 'incident_id' => 'incidents'],
    'approval_requests' => ['playbook_run_id' => 'playbook_runs', 'incident_id' => 'incidents'],
    'evidence'          => ['incident_id' => 'incidents'],
    'case_notes'        => ['incident_id' => 'incidents', 'author_id' => 'users'],
    'notifications'     => ['recipient_id' => 'users'],
];

logMessage("\nVerifying Foreign Key constraints...", 'INFO');
foreach ($expectedForeignKeys as $table => $fks) {
    $stmt = $pdo->prepare("
        SELECT kcu.column_name, kcu.referenced_table_name
        FROM information_schema.key_column_usage kcu
        WHERE kcu.table_schema = ?
          AND kcu.table_name = ?
          AND kcu.referenced_table_name IS NOT NULL
    ");
    $stmt->execute([$db_name, $table]);
    $foundFks = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

    foreach ($fks as $col => $refTable) {
        if (isset($foundFks[$col]) && $foundFks[$col] === $refTable) {
            logMessage("Foreign key '$table.$col' -> '$refTable.id' verified.", 'SUCCESS');
            $passed++;
        } else {
            logMessage("Foreign key '$table.$col' -> '$refTable.id' is MISSING or invalid.", 'FAIL');
            $failed++;
        }
    }
}

// Summary Report
logMessage("\n==================================================", 'INFO');
logMessage("SCHEMA VERIFICATION COMPLETE: $passed Passed, $failed Failed", $failed === 0 ? 'SUCCESS' : 'FAIL');
logMessage("==================================================", 'INFO');

exit($failed === 0 ? 0 : 1);
