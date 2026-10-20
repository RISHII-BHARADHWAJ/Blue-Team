-- Separate external threat-intelligence listings from observed SIEM events.
-- Safe for an existing database: adds a table; does not rewrite legacy logs.
CREATE TABLE IF NOT EXISTS threat_feed_indicators (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    provider VARCHAR(64) NOT NULL,
    indicator_type ENUM('IPV4','IPV6','DOMAIN','URL','MD5','SHA256') NOT NULL,
    indicator_value VARCHAR(255) NOT NULL,
    threat_type VARCHAR(100) NULL,
    malware_family VARCHAR(150) NULL,
    port SMALLINT UNSIGNED NULL,
    source_first_seen DATETIME NULL,
    source_last_seen DATETIME NULL,
    fetched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_feed_indicator (provider, indicator_type, indicator_value),
    INDEX idx_feed_indicator_value (indicator_value),
    INDEX idx_feed_provider_fetched (provider, fetched_at),
    INDEX idx_feed_last_seen (source_last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
