-- Additive migration; rerunning preserves operator settings and findings.
CREATE TABLE IF NOT EXISTS detection_rules (
    rule_key VARCHAR(64) PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    severity ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    threshold_count SMALLINT UNSIGNED NOT NULL,
    window_seconds INT UNSIGNED NOT NULL,
    revision INT UNSIGNED NOT NULL DEFAULT 1,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL DEFAULT 'migration'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT IGNORE INTO detection_rules (rule_key, name, severity, threshold_count, window_seconds) VALUES
('auth_failures', 'Repeated authentication failures', 'HIGH', 5, 300),
('source_ip_intel', 'Source IP listed in threat intelligence', 'MEDIUM', 1, 3600);

-- Indexed projection of structured authentication-failure evidence, including
-- failures received while a rule is disabled. Source timestamps never drive windows.
CREATE TABLE IF NOT EXISTS detection_observations (
    evidence_id BIGINT UNSIGNED PRIMARY KEY,
    group_key CHAR(64) NOT NULL,
    received_at DATETIME NOT NULL,
    INDEX idx_detection_window (group_key, received_at, evidence_id),
    FOREIGN KEY (evidence_id) REFERENCES event_evidence(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS detection_findings (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    rule_key VARCHAR(64) NOT NULL,
    rule_revision INT UNSIGNED NOT NULL,
    group_key CHAR(64) NOT NULL,
    trigger_evidence_id BIGINT UNSIGNED NOT NULL,
    is_simulated TINYINT(1) NOT NULL,
    severity ENUM('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL,
    summary VARCHAR(500) NOT NULL,
    rule_snapshot LONGTEXT NOT NULL CHECK (JSON_VALID(rule_snapshot)),
    context_json LONGTEXT NOT NULL CHECK (JSON_VALID(context_json)),
    created_at DATETIME NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    UNIQUE KEY uq_detection_trigger (rule_key, trigger_evidence_id),
    INDEX idx_detection_cooldown (rule_key, rule_revision, group_key, created_at),
    INDEX idx_detection_kind (is_simulated, id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT,
    FOREIGN KEY (rule_key) REFERENCES detection_rules(rule_key) ON DELETE RESTRICT,
    FOREIGN KEY (trigger_evidence_id) REFERENCES event_evidence(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS detection_finding_evidence (
    finding_id BIGINT UNSIGNED NOT NULL,
    evidence_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (finding_id, evidence_id),
    FOREIGN KEY (finding_id) REFERENCES detection_findings(id) ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id) REFERENCES event_evidence(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
