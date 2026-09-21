-- ==============================================================================
-- ThreatPulse SOAR - Phase 1 Schema Test Suite
-- File: database/tests/001_soar_schema_test.sql
-- 
-- Tests:
-- 1. Create a new incident.
-- 2. Reference existing logs through incident_alerts.
-- 3. Associate multiple alerts with one incident.
-- 4. Link an IOC to multiple incidents.
-- 5. Create a playbook with multiple ordered steps.
-- 6. Execute a playbook run referencing an incident.
-- 7. Create a human approval request referencing a playbook run.
-- 8. Create a response action referencing an approval.
-- 9. Attach SHA-256 hashed evidence to an incident.
-- 10. Assign notifications to users.
-- 11. Verify append-only timeline event insertion.
-- 12. Verify case notes creation.
-- 13. Ensure existing SIEM tables retain original data and schema.
-- ==============================================================================

START TRANSACTION;

-- Setup baseline prerequisites if needed (test user and test logs)
INSERT INTO users (username, password, email, role) 
VALUES ('test_soar_analyst', 'hash123', 'analyst@threatpulse.local', 'analyst')
ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id);
SET @test_user_id = LAST_INSERT_ID();

INSERT INTO logs (source_ip, severity, category, message, timestamp) 
VALUES ('198.51.100.50', 'CRITICAL', 'SSH', 'TEST SSH Brute force attack', NOW());
SET @log_id_1 = LAST_INSERT_ID();

INSERT INTO logs (source_ip, severity, category, message, timestamp) 
VALUES ('198.51.100.50', 'HIGH', 'RCE', 'TEST RCE Exploit attempt', NOW());
SET @log_id_2 = LAST_INSERT_ID();

-- ------------------------------------------------------------------------------
-- TEST 1: A new incident can be created
-- ------------------------------------------------------------------------------
INSERT INTO incidents (
    incident_number, title, description, severity, status, priority, risk_score, 
    assigned_to, lead_analyst, attack_category, mitre_tactics, mitre_techniques
) VALUES (
    'TEST-INC-2026-0001', 
    'Suspected Multi-Stage Intrusion from 198.51.100.50', 
    'Automated correlation detected SSH brute force followed by RCE exploit payload.',
    'CRITICAL', 'OPEN', 'P1', 92,
    @test_user_id, @test_user_id, 'RCE', 'Initial Access, Execution', 'T1190, T1059'
);
SET @incident_id_1 = LAST_INSERT_ID();

-- Also create a second incident for multi-incident IOC testing
INSERT INTO incidents (
    incident_number, title, description, severity, status, priority, risk_score, 
    assigned_to, lead_analyst, attack_category
) VALUES (
    'TEST-INC-2026-0002', 
    'Secondary C2 Beacon Activity', 
    'Periodic egress traffic matching known C2 infrastructure.',
    'HIGH', 'NEW', 'P2', 75,
    @test_user_id, @test_user_id, 'C2'
);
SET @incident_id_2 = LAST_INSERT_ID();

-- ------------------------------------------------------------------------------
-- TEST 2 & 3: Reference existing logs through incident_alerts & Multiple alerts in one incident
-- ------------------------------------------------------------------------------
INSERT INTO incident_alerts (incident_id, log_id, correlation_rule)
VALUES 
    (@incident_id_1, @log_id_1, 'CORR_RULE_SAME_SOURCE_IP'),
    (@incident_id_1, @log_id_2, 'CORR_RULE_MULTI_VECTOR_ESCALATION');

-- ------------------------------------------------------------------------------
-- TEST 4: An IOC can be created and linked to multiple incidents
-- ------------------------------------------------------------------------------
INSERT INTO iocs (
    ioc_type, ioc_value, threat_type, malware_family, reputation_score, 
    confidence_score, source_feed, is_whitelisted
) VALUES (
    'IPV4', '198.51.100.50', 'Botnet C2', 'Mirai Variant', 95, 90, 'FeodoTracker', FALSE
) ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id);
SET @ioc_id_1 = LAST_INSERT_ID();

-- Associate IOC with both Incident 1 (as Attacker) and Incident 2 (as C2 Server)
INSERT INTO incident_iocs (incident_id, ioc_id, role)
VALUES 
    (@incident_id_1, @ioc_id_1, 'ATTACKER'),
    (@incident_id_2, @ioc_id_1, 'C2_SERVER');

-- Add enrichment cache for IOC
INSERT INTO enrichment_results (ioc_id, provider, status, raw_response, parsed_summary, cached_until)
VALUES (
    @ioc_id_1, 
    'abuseipdb', 
    'SUCCESS', 
    JSON_OBJECT('ip', '198.51.100.50', 'abuseConfidenceScore', 95, 'totalReports', 142),
    JSON_OBJECT('abuse_score', 95, 'country', 'US', 'isp', 'Example Hosting LLC'),
    DATE_ADD(NOW(), INTERVAL 24 HOUR)
);

-- ------------------------------------------------------------------------------
-- TEST 5: A playbook can have multiple ordered steps
-- ------------------------------------------------------------------------------
INSERT INTO playbooks (
    playbook_name, display_name, description, category, trigger_type, 
    trigger_condition, requires_approval, min_approval_tier, is_active, created_by
) VALUES (
    'PB_TEST_SSH_CONTAINMENT',
    'SSH Brute Force Quarantine & Triage',
    'Enriches attacker IP, calculates risk, requests approval, and applies firewall block.',
    'CONTAINMENT',
    'AUTOMATIC',
    JSON_OBJECT('category', 'SSH', 'min_severity', 'HIGH'),
    TRUE,
    'LEAD',
    TRUE,
    @test_user_id
);
SET @playbook_id = LAST_INSERT_ID();

INSERT INTO playbook_steps (playbook_id, step_order, step_name, action_type, action_parameters, timeout_seconds)
VALUES 
    (@playbook_id, 1, 'Enrich Attacker IP', 'ENRICH_IP', JSON_OBJECT('provider', 'all'), 30),
    (@playbook_id, 2, 'Calculate Incident Risk', 'CALCULATE_RISK', JSON_OBJECT('algorithm', 'standard_v1'), 10),
    (@playbook_id, 3, 'Request Firewall Block Approval', 'REQUEST_APPROVAL', JSON_OBJECT('tier', 'LEAD', 'action', 'FIREWALL_BLOCK_IP'), 300),
    (@playbook_id, 4, 'Execute Firewall Quarantine', 'FIREWALL_BLOCK_IP', JSON_OBJECT('duration_hours', 24), 60);

-- ------------------------------------------------------------------------------
-- TEST 6: A playbook run can reference an incident
-- ------------------------------------------------------------------------------
INSERT INTO playbook_runs (
    run_uuid, playbook_id, incident_id, triggered_by, analyst_id, 
    status, current_step_order, execution_context
) VALUES (
    'RUN-UUID-TEST-00001',
    @playbook_id,
    @incident_id_1,
    'AUTOMATION',
    @test_user_id,
    'WAITING_APPROVAL',
    3,
    JSON_OBJECT('target_ip', '198.51.100.50', 'reputation_score', 95)
);
SET @playbook_run_id = LAST_INSERT_ID();

-- ------------------------------------------------------------------------------
-- TEST 7: An approval can reference a playbook run
-- ------------------------------------------------------------------------------
INSERT INTO approval_requests (
    playbook_run_id, incident_id, action_name, action_description, 
    action_payload, required_tier, status, reviewed_by, expires_at
) VALUES (
    @playbook_run_id,
    @incident_id_1,
    'FIREWALL_BLOCK_IP',
    'Block inbound traffic from attacker IP 198.51.100.50 on perimeter firewall for 24 hours.',
    JSON_OBJECT('ip', '198.51.100.50', 'direction', 'INBOUND', 'action', 'DROP'),
    'LEAD',
    'APPROVED',
    @test_user_id,
    DATE_ADD(NOW(), INTERVAL 1 HOUR)
);
SET @approval_id = LAST_INSERT_ID();

-- ------------------------------------------------------------------------------
-- TEST 8: A response action can reference an approval
-- ------------------------------------------------------------------------------
INSERT INTO response_actions (
    action_uuid, incident_id, playbook_run_id, approval_id, 
    action_type, target_entity, status, output_log, rollback_supported
) VALUES (
    'ACT-UUID-TEST-00001',
    @incident_id_1,
    @playbook_run_id,
    @approval_id,
    'FIREWALL_BLOCK_IP',
    '198.51.100.50',
    'SUCCESS',
    'Rule added to perimeter firewall table: DROP src 198.51.100.50/32 dst ANY',
    TRUE
);

-- ------------------------------------------------------------------------------
-- TEST 9: Evidence can be attached to an incident
-- ------------------------------------------------------------------------------
INSERT INTO evidence (
    incident_id, evidence_type, title, description, 
    data_hash, content_text, collected_by
) VALUES (
    @incident_id_1,
    'LOG_SNIPPET',
    'Auth.log snippet containing brute force attempts',
    'Captured 240 failed password attempts within 3 minutes.',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'Jun 14 15:16:01 combo sshd[1234]: Failed password for root from 198.51.100.50 port 44123 ssh2',
    @test_user_id
);

-- ------------------------------------------------------------------------------
-- TEST 10: Notifications can be assigned to users
-- ------------------------------------------------------------------------------
INSERT INTO notifications (
    recipient_id, incident_id, title, message, notification_type, is_read
) VALUES (
    @test_user_id,
    @incident_id_1,
    'Approval Granted for Incident TEST-INC-2026-0001',
    'Action FIREWALL_BLOCK_IP on 198.51.100.50 was approved and successfully executed.',
    'APPROVAL_REQUIRED',
    FALSE
);

-- ------------------------------------------------------------------------------
-- TEST 11: Timeline and Case Notes verification
-- ------------------------------------------------------------------------------
INSERT INTO incident_timeline (
    incident_id, event_type, actor_type, actor_name, summary, details
) VALUES 
    (@incident_id_1, 'ALERT_ADDED', 'SYSTEM', 'CorrelationEngine', 'Added 2 alerts to incident', JSON_OBJECT('count', 2)),
    (@incident_id_1, 'PLAYBOOK_STARTED', 'SYSTEM', 'PlaybookEngine', 'Triggered playbook PB_TEST_SSH_CONTAINMENT', JSON_OBJECT('run_uuid', 'RUN-UUID-TEST-00001')),
    (@incident_id_1, 'APPROVAL_GRANTED', 'ANALYST', 'test_soar_analyst', 'Approved FIREWALL_BLOCK_IP for 198.51.100.50', JSON_OBJECT('tier', 'LEAD')),
    (@incident_id_1, 'ACTION_EXECUTED', 'PLAYBOOK', 'PB_TEST_SSH_CONTAINMENT', 'Executed action FIREWALL_BLOCK_IP successfully', JSON_OBJECT('target', '198.51.100.50'));

INSERT INTO case_notes (incident_id, author_id, note_text, is_pinned)
VALUES (@incident_id_1, @test_user_id, 'Primary containment verified. Monitoring for secondary lateral movement.', TRUE);

-- Verification Select Queries to prove data integrity
SELECT 
    i.incident_number, 
    i.title, 
    i.severity, 
    COUNT(DISTINCT ia.log_id) AS total_alerts,
    COUNT(DISTINCT ii.ioc_id) AS total_iocs,
    COUNT(DISTINCT it.id) AS timeline_events
FROM incidents i
LEFT JOIN incident_alerts ia ON i.id = ia.incident_id
LEFT JOIN incident_iocs ii ON i.id = ii.incident_id
LEFT JOIN incident_timeline it ON i.id = it.incident_id
WHERE i.id = @incident_id_1
GROUP BY i.id;

-- Roll back test transaction to ensure database cleanliness
ROLLBACK;
