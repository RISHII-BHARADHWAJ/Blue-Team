-- Append-only provenance for newly accepted sensor alerts. No historical backfill:
-- legacy logs can contain external feed entries and cannot be reliably reclassified.
CREATE TABLE IF NOT EXISTS event_evidence (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    log_id INT NOT NULL,
    fingerprint CHAR(64) NOT NULL,
    source VARCHAR(100) NOT NULL,
    source_type VARCHAR(50) NOT NULL,
    source_event_id VARCHAR(64) NULL,
    submitted_by VARCHAR(255) NOT NULL,
    is_simulated TINYINT(1) NOT NULL DEFAULT 0,
    event_timestamp DATETIME NOT NULL,
    received_at DATETIME NOT NULL,
    timestamp_origin ENUM('source', 'receipt_fallback') NOT NULL,
    canonical_json LONGTEXT NOT NULL CHECK (JSON_VALID(canonical_json)),
    raw_payload LONGTEXT NOT NULL CHECK (JSON_VALID(raw_payload)),
    payload_encoding ENUM('http_body', 'reencoded_json') NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    UNIQUE KEY uq_evidence_log (log_id),
    INDEX idx_evidence_received (received_at, id),
    INDEX idx_evidence_source (source, received_at),
    INDEX idx_evidence_simulated (is_simulated, received_at),
    CONSTRAINT fk_evidence_log FOREIGN KEY (log_id) REFERENCES logs(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
