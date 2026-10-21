-- Additive, rerunnable: existing indicators and operator settings are preserved.
CREATE TABLE IF NOT EXISTS feed_sources (
    provider VARCHAR(64) PRIMARY KEY,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    refresh_seconds INT UNSIGNED NOT NULL,
    revision INT UNSIGNED NOT NULL DEFAULT 1,
    last_attempt_at DATETIME NULL,
    last_success_at DATETIME NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255) NOT NULL DEFAULT 'migration'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
INSERT IGNORE INTO feed_sources (provider, refresh_seconds) VALUES
('feodo_tracker', 300), ('emerging_threats', 1800), ('cins_army', 1800), ('blocklist_de', 1800);

CREATE TABLE IF NOT EXISTS feed_collection_runs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    provider VARCHAR(64) NOT NULL,
    source_url VARCHAR(255) NOT NULL,
    trigger_kind ENUM('MANUAL','SCHEDULED') NOT NULL,
    config_revision INT UNSIGNED NOT NULL,
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME NULL,
    status ENUM('RUNNING','SUCCESS','PARTIAL','FAILED','INTERRUPTED') NOT NULL,
    http_status SMALLINT UNSIGNED NULL,
    bytes_received INT UNSIGNED NOT NULL DEFAULT 0,
    processed_count INT UNSIGNED NOT NULL DEFAULT 0,
    inserted_count INT UNSIGNED NOT NULL DEFAULT 0,
    existing_count INT UNSIGNED NOT NULL DEFAULT 0,
    invalid_count INT UNSIGNED NOT NULL DEFAULT 0,
    duplicate_count INT UNSIGNED NOT NULL DEFAULT 0,
    truncated TINYINT(1) NOT NULL DEFAULT 0,
    elapsed_ms BIGINT UNSIGNED NULL,
    detail VARCHAR(500) NOT NULL,
    INDEX idx_feed_runs (provider, id),
    INDEX idx_feed_run_status (status, id),
    FOREIGN KEY (provider) REFERENCES feed_sources(provider) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
