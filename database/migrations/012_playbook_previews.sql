-- Additive, rerunnable request-to-run mapping for retry-safe analyst previews.
CREATE TABLE IF NOT EXISTS playbook_preview_requests (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    request_key CHAR(32) NOT NULL,
    incident_id BIGINT UNSIGNED NOT NULL,
    playbook_id BIGINT UNSIGNED NOT NULL,
    playbook_version INT UNSIGNED NOT NULL,
    run_id BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_preview_request (user_id, request_key),
    UNIQUE KEY uq_preview_run (run_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE RESTRICT,
    FOREIGN KEY (playbook_id) REFERENCES playbooks(id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id) REFERENCES playbook_runs(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
