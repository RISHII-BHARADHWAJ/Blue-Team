-- SIEM tables required by ThreatPulse before SOAR migrations.
-- Runs after database.sql and before database/migrations/001_create_soar_schema.sql.

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_ip VARCHAR(45),
    severity ENUM('CRITICAL','HIGH','WARNING','INFO','LOW') DEFAULT 'INFO',
    category VARCHAR(50) DEFAULT 'Other',
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_source_ip (source_ip),
    INDEX idx_timestamp (timestamp),
    INDEX idx_severity (severity),
    INDEX idx_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ip_geo (
    ip VARCHAR(45) PRIMARY KEY,
    country_code VARCHAR(5),
    country_name VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10,6),
    longitude DECIMAL(10,6),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
