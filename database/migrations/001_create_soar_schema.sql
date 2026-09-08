-- ==============================================================================
-- ThreatPulse SIEM + SOAR Platform
-- Migration: 001_create_soar_schema.sql
-- Description: Creates the 15 core database entities for the SOAR subsystem.
-- Engine: InnoDB | Charset: utf8mb4 | Collation: utf8mb4_unicode_ci
-- Compatibility: MariaDB 10.5+ / MySQL 8.0+
-- 
-- NON-DESTRUCTIVE & ADDITIVE:
-- Preserves all existing SIEM tables (logs, ip_geo, users, audit_log, activity_logs, rate_limits)
-- ==============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ------------------------------------------------------------------------------
-- 1. INCIDENTS
-- Core Case Management entity representing correlated security incidents
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_number VARCHAR(32) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    severity ENUM('CRITICAL','HIGH','MEDIUM','LOW','INFO') NOT NULL DEFAULT 'MEDIUM',
    status ENUM('NEW','OPEN','INVESTIGATING','CONTAINED','RESOLVED','CLOSED') NOT NULL DEFAULT 'NEW',
    priority ENUM('P1','P2','P3','P4') NOT NULL DEFAULT 'P3',
    risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
    assigned_to INT NULL,
    lead_analyst INT NULL,
    attack_category VARCHAR(50) NULL,
    mitre_tactics VARCHAR(500) NULL,
    mitre_techniques VARCHAR(500) NULL,
    contained_at DATETIME NULL,
    resolved_at DATETIME NULL,
    closed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT uq_incidents_number UNIQUE (incident_number),
    CONSTRAINT fk_incidents_assigned_to FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_incidents_lead_analyst FOREIGN KEY (lead_analyst) REFERENCES users(id) ON DELETE SET NULL,

    INDEX idx_incidents_status (status),
    INDEX idx_incidents_severity (severity),
    INDEX idx_incidents_priority (priority),
    INDEX idx_incidents_created_at (created_at),
    INDEX idx_incidents_assigned_to (assigned_to),
    INDEX idx_incidents_category (attack_category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 2. INCIDENT_ALERTS
-- Associates existing SIEM logs with an incident (Many-to-Many junction)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_alerts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    log_id INT NOT NULL,
    correlation_rule VARCHAR(100) NULL,
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_incident_alerts (incident_id, log_id),
    CONSTRAINT fk_incident_alerts_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_alerts_log FOREIGN KEY (log_id) REFERENCES logs(id) ON DELETE CASCADE,

    INDEX idx_incident_alerts_incident_id (incident_id),
    INDEX idx_incident_alerts_log_id (log_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 3. INCIDENT_EVENTS
-- Associates raw telemetry events (WAF, auth_log, Apache, network) with an incident
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    event_source VARCHAR(50) NOT NULL,
    raw_event_id VARCHAR(64) NULL,
    event_timestamp DATETIME NOT NULL,
    summary VARCHAR(255) NULL,
    raw_payload JSON NULL,
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_incident_events_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,

    INDEX idx_incident_events_incident_id (incident_id),
    INDEX idx_incident_events_timestamp (event_timestamp),
    INDEX idx_incident_events_raw_event_id (raw_event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 4. INCIDENT_TIMELINE
-- Chronological, append-oriented incident event log for auditability
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_timeline (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    event_type ENUM(
        'ALERT_ADDED',
        'STATUS_CHANGE',
        'SEVERITY_CHANGE',
        'PLAYBOOK_STARTED',
        'PLAYBOOK_STEP',
        'APPROVAL_REQUESTED',
        'APPROVAL_GRANTED',
        'APPROVAL_REJECTED',
        'ACTION_EXECUTED',
        'EVIDENCE_ATTACHED',
        'NOTE_ADDED'
    ) NOT NULL,
    actor_type ENUM('SYSTEM','ANALYST','PLAYBOOK') NOT NULL,
    actor_name VARCHAR(100) NOT NULL,
    summary VARCHAR(255) NOT NULL,
    details JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_incident_timeline_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,

    INDEX idx_incident_timeline_incident_id (incident_id),
    INDEX idx_incident_timeline_created_at (created_at),
    INDEX idx_incident_timeline_event_type (event_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 5. IOCS
-- Indicator of Compromise global registry
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iocs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ioc_type ENUM('IPV4','IPV6','DOMAIN','URL','MD5','SHA256','EMAIL') NOT NULL,
    ioc_value VARCHAR(500) NOT NULL,
    threat_type VARCHAR(100) NULL,
    malware_family VARCHAR(100) NULL,
    reputation_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
    confidence_score TINYINT UNSIGNED NOT NULL DEFAULT 50,
    source_feed VARCHAR(100) NULL,
    is_whitelisted BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_iocs_type_value UNIQUE (ioc_type, ioc_value),

    INDEX idx_iocs_type (ioc_type),
    INDEX idx_iocs_value (ioc_value(255)),
    INDEX idx_iocs_reputation (reputation_score),
    INDEX idx_iocs_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 6. INCIDENT_IOCS
-- Associates indicators with an incident and contextualizes their role
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_iocs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    ioc_id BIGINT UNSIGNED NOT NULL,
    role ENUM('ATTACKER','TARGET','C2_SERVER','PAYLOAD_URL','DROPPED_FILE','EXFILTRATION_HOST') NOT NULL DEFAULT 'ATTACKER',
    discovered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_incident_iocs UNIQUE (incident_id, ioc_id),
    CONSTRAINT fk_incident_iocs_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_incident_iocs_ioc FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,

    INDEX idx_incident_iocs_incident_id (incident_id),
    INDEX idx_incident_iocs_ioc_id (ioc_id),
    INDEX idx_incident_iocs_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 7. ENRICHMENT_RESULTS
-- Caches external threat intelligence lookups per IOC
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS enrichment_results (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ioc_id BIGINT UNSIGNED NOT NULL,
    provider VARCHAR(50) NOT NULL,
    status ENUM('SUCCESS','FAILED','RATE_LIMITED') NOT NULL,
    raw_response JSON NULL,
    parsed_summary JSON NULL,
    cached_until DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_enrichment_results_ioc FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,

    INDEX idx_enrichment_ioc_provider (ioc_id, provider),
    INDEX idx_enrichment_cached_until (cached_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 8. PLAYBOOKS
-- Declarative automation workflow definitions
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS playbooks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    playbook_name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT NULL,
    category ENUM('CONTAINMENT','ENRICHMENT','INVESTIGATION','REMEDIATION','NOTIFICATION') NOT NULL,
    trigger_type ENUM('AUTOMATIC','MANUAL','SCHEDULED') NOT NULL DEFAULT 'MANUAL',
    trigger_condition JSON NULL,
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    min_approval_tier ENUM('TIER1','TIER2','LEAD','ADMIN') NOT NULL DEFAULT 'LEAD',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    version INT UNSIGNED NOT NULL DEFAULT 1,
    created_by INT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT uq_playbooks_name UNIQUE (playbook_name),
    CONSTRAINT fk_playbooks_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,

    INDEX idx_playbooks_category (category),
    INDEX idx_playbooks_trigger_type (trigger_type),
    INDEX idx_playbooks_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 9. PLAYBOOK_STEPS
-- Atomic sequential or branched steps for a playbook definition
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS playbook_steps (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    playbook_id BIGINT UNSIGNED NOT NULL,
    step_order INT UNSIGNED NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    action_parameters JSON NULL,
    on_success_step BIGINT UNSIGNED NULL,
    on_failure_step BIGINT UNSIGNED NULL,
    timeout_seconds INT UNSIGNED NOT NULL DEFAULT 60,

    CONSTRAINT uq_playbook_step_order UNIQUE (playbook_id, step_order),
    CONSTRAINT fk_playbook_steps_playbook FOREIGN KEY (playbook_id) REFERENCES playbooks(id) ON DELETE CASCADE,

    INDEX idx_playbook_steps_playbook_id (playbook_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 10. PLAYBOOK_RUNS
-- Execution runtime instance of a playbook
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS playbook_runs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    run_uuid VARCHAR(64) NOT NULL,
    playbook_id BIGINT UNSIGNED NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    triggered_by ENUM('AUTOMATION','ANALYST') NOT NULL,
    analyst_id INT NULL,
    status ENUM('PENDING','RUNNING','WAITING_APPROVAL','COMPLETED','FAILED','CANCELLED') NOT NULL DEFAULT 'PENDING',
    current_step_order INT UNSIGNED NOT NULL DEFAULT 1,
    execution_context JSON NULL,
    error_message TEXT NULL,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME NULL,

    CONSTRAINT uq_playbook_runs_uuid UNIQUE (run_uuid),
    CONSTRAINT fk_playbook_runs_playbook FOREIGN KEY (playbook_id) REFERENCES playbooks(id) ON DELETE RESTRICT,
    CONSTRAINT fk_playbook_runs_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_playbook_runs_analyst FOREIGN KEY (analyst_id) REFERENCES users(id) ON DELETE SET NULL,

    INDEX idx_playbook_runs_status (status),
    INDEX idx_playbook_runs_incident_id (incident_id),
    INDEX idx_playbook_runs_playbook_id (playbook_id),
    INDEX idx_playbook_runs_started_at (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 11. APPROVAL_REQUESTS
-- Human-in-the-Loop governance records for gated response actions
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approval_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    playbook_run_id BIGINT UNSIGNED NOT NULL,
    incident_id BIGINT UNSIGNED NOT NULL,
    action_name VARCHAR(100) NOT NULL,
    action_description TEXT NOT NULL,
    action_payload JSON NOT NULL,
    required_tier ENUM('TIER1','TIER2','LEAD','ADMIN') NOT NULL DEFAULT 'LEAD',
    status ENUM('PENDING','APPROVED','REJECTED','EXPIRED') NOT NULL DEFAULT 'PENDING',
    requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_by INT NULL,
    reviewed_at DATETIME NULL,
    rejection_reason TEXT NULL,
    expires_at DATETIME NOT NULL,

    CONSTRAINT fk_approvals_playbook_run FOREIGN KEY (playbook_run_id) REFERENCES playbook_runs(id) ON DELETE CASCADE,
    CONSTRAINT fk_approvals_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_approvals_reviewed_by FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,

    INDEX idx_approval_status (status),
    INDEX idx_approval_incident_id (incident_id),
    INDEX idx_approval_playbook_run_id (playbook_run_id),
    INDEX idx_approval_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 12. RESPONSE_ACTIONS
-- Audit and execution log of atomic mitigation/containment actions
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS response_actions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    action_uuid VARCHAR(64) NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    playbook_run_id BIGINT UNSIGNED NULL,
    approval_id BIGINT UNSIGNED NULL,
    action_type VARCHAR(50) NOT NULL,
    target_entity VARCHAR(255) NOT NULL,
    status ENUM('QUEUED','IN_PROGRESS','SUCCESS','FAILED','ROLLED_BACK') NOT NULL DEFAULT 'QUEUED',
    dispatched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    executed_at DATETIME NULL,
    output_log TEXT NULL,
    rollback_supported BOOLEAN NOT NULL DEFAULT FALSE,
    is_rolled_back BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT uq_response_actions_uuid UNIQUE (action_uuid),
    CONSTRAINT fk_response_actions_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL,
    CONSTRAINT fk_response_actions_run FOREIGN KEY (playbook_run_id) REFERENCES playbook_runs(id) ON DELETE SET NULL,
    CONSTRAINT fk_response_actions_approval FOREIGN KEY (approval_id) REFERENCES approval_requests(id) ON DELETE SET NULL,

    INDEX idx_response_actions_status (status),
    INDEX idx_response_actions_incident_id (incident_id),
    INDEX idx_response_actions_playbook_run_id (playbook_run_id),
    INDEX idx_response_actions_approval_id (approval_id),
    INDEX idx_response_actions_dispatched_at (dispatched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 13. EVIDENCE
-- Cryptographically hashed forensic evidence artifacts attached to incidents
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    evidence_type ENUM('LOG_SNIPPET','NETWORK_PCAP','FILE_HASH','MEMORY_DUMP_META','HTTP_REQUEST_PAYLOAD','SCREENSHOT') NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    data_hash VARCHAR(64) NOT NULL,
    content_text MEDIUMTEXT NULL,
    file_path VARCHAR(255) NULL,
    collected_by INT NULL,
    collected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_evidence_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_evidence_collected_by FOREIGN KEY (collected_by) REFERENCES users(id) ON DELETE SET NULL,

    INDEX idx_evidence_incident_id (incident_id),
    INDEX idx_evidence_type (evidence_type),
    INDEX idx_evidence_hash (data_hash),
    INDEX idx_evidence_collected_at (collected_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 14. CASE_NOTES
-- Collaborative analyst investigation notes per incident
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS case_notes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    author_id INT NOT NULL,
    note_text TEXT NOT NULL,
    is_pinned BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_case_notes_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    CONSTRAINT fk_case_notes_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,

    INDEX idx_case_notes_incident_id (incident_id),
    INDEX idx_case_notes_author_id (author_id),
    INDEX idx_case_notes_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 15. NOTIFICATIONS
-- Real-time system and workflow notifications for analysts
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    recipient_id INT NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    notification_type ENUM('APPROVAL_REQUIRED','INCIDENT_ASSIGNED','PLAYBOOK_FAILED','SLA_BREACH') NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_notifications_recipient FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_notifications_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,

    INDEX idx_notifications_recipient (recipient_id, is_read),
    INDEX idx_notifications_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
