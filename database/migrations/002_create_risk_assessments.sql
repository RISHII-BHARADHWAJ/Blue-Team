-- ==============================================================================
-- ThreatPulse SIEM + SOAR Platform
-- Migration: 002_create_risk_assessments.sql
-- Description: Creates the risk_assessments table for storing historical,
--              explainable incident risk assessments and factor breakdowns.
-- Engine: InnoDB | Charset: utf8mb4 | Collation: utf8mb4_unicode_ci
-- Compatibility: MariaDB 10.5+ / MySQL 8.0+
-- 
-- NON-DESTRUCTIVE & ADDITIVE:
-- Preserves all existing SIEM tables (logs, ip_geo, users, audit_log, etc.)
-- and Phase 1 SOAR tables.
-- ==============================================================================

SET FOREIGN_KEY_CHECKS = 0;

CREATE TABLE IF NOT EXISTS risk_assessments (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    incident_id BIGINT UNSIGNED NOT NULL,
    score TINYINT UNSIGNED NOT NULL,
    priority ENUM('P1','P2','P3','P4') NOT NULL,
    confidence ENUM('HIGH','MEDIUM','LOW') NOT NULL DEFAULT 'MEDIUM',
    factor_breakdown JSON NOT NULL,
    policy_version VARCHAR(32) NOT NULL,
    calculated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    calculated_by VARCHAR(100) NOT NULL DEFAULT 'system',

    CONSTRAINT fk_risk_assessments_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,

    INDEX idx_risk_assessments_incident (incident_id),
    INDEX idx_risk_assessments_calculated_at (calculated_at),
    INDEX idx_risk_assessments_score (score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
