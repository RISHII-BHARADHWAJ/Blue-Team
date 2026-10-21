-- MariaDB additive, rerunnable migration. Existing incidents remain real.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS is_simulated TINYINT(1) NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_incident_simulated ON incidents (is_simulated, status, created_at);
CREATE TABLE IF NOT EXISTS demo_sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    request_key CHAR(32) NOT NULL,
    created_by INT NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    finding_id BIGINT UNSIGNED NULL,
    playbook_run_id BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_demo_request (created_by, request_key),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT,
    FOREIGN KEY (finding_id) REFERENCES detection_findings(id) ON DELETE RESTRICT,
    FOREIGN KEY (playbook_run_id) REFERENCES playbook_runs(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO playbooks (playbook_name, display_name, description, category, trigger_type, requires_approval)
VALUES ('simulated_investigation_v1', 'Simulated investigation walkthrough', 'Preview context, approval and notification steps. Simulated incidents always enforce dry-run.', 'INVESTIGATION', 'MANUAL', 0);
INSERT IGNORE INTO playbook_steps (playbook_id, step_order, step_name, action_type, action_parameters)
SELECT id, 1, 'Preview incident context', 'COLLECT_INCIDENT_CONTEXT', '{}' FROM playbooks WHERE playbook_name='simulated_investigation_v1';
INSERT IGNORE INTO playbook_steps (playbook_id, step_order, step_name, action_type, action_parameters)
SELECT id, 2, 'Preview approval gate', 'REQUEST_APPROVAL', '{}' FROM playbooks WHERE playbook_name='simulated_investigation_v1';
INSERT IGNORE INTO playbook_steps (playbook_id, step_order, step_name, action_type, action_parameters)
SELECT id, 3, 'Preview analyst notification', 'NOTIFY_ANALYST', '{"title":"Simulated investigation","message":"Training preview only"}' FROM playbooks WHERE playbook_name='simulated_investigation_v1';
