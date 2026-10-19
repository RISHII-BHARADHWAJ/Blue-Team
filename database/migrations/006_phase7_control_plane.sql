-- ==============================================================================
-- ThreatPulse SIEM + SOAR Platform
-- Migration: 006_phase7_control_plane.sql
-- Description: Extends schema for Phase 7 SOC Approval & Response Control Plane.
--
-- NON-DESTRUCTIVE & ADDITIVE:
--   - Ensures notifications table structure, foreign keys, and indexes
--   - Adds decided_at and extends status ENUM on approval_requests (CANCELLED, EXPIRED)
--   - Adds playbook_version tracking column to playbook_runs
--   - Ensures playbooks supports versioning via (playbook_name, version)
--   - Leaves all existing SIEM tables (logs, ip_geo, users, audit_log, rate_limits) untouched
-- ==============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ------------------------------------------------------------------------------
-- 1. NOTIFICATIONS TABLE (IDEMPOTENT CREATION & EXTENSION)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    recipient_id INT NOT NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'APPROVAL_REQUESTED',
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    approval_id BIGINT UNSIGNED NULL,
    playbook_run_id BIGINT UNSIGNED NULL,
    read_at DATETIME NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_p7_notifications_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_p7_notifications_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,

    INDEX idx_p7_notifications_user_read (user_id, is_read),
    INDEX idx_p7_notifications_type (type),
    INDEX idx_p7_notifications_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------------------------
-- 2. APPROVAL_REQUESTS EXTENSIONS
-- ------------------------------------------------------------------------------
-- Ensure decided_at column exists
ALTER TABLE approval_requests
    ADD COLUMN IF NOT EXISTS decided_at DATETIME NULL AFTER reviewed_at;

-- Ensure status supports PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED
ALTER TABLE approval_requests
    MODIFY COLUMN status ENUM('PENDING','APPROVED','REJECTED','EXPIRED','CANCELLED') NOT NULL DEFAULT 'PENDING';

-- ------------------------------------------------------------------------------
-- 3. PLAYBOOK_RUNS VERSION TRACKING
-- ------------------------------------------------------------------------------
-- Lock active playbook runs to the specific playbook definition version
ALTER TABLE playbook_runs
    ADD COLUMN IF NOT EXISTS playbook_version INT UNSIGNED NOT NULL DEFAULT 1 AFTER playbook_id;

-- ------------------------------------------------------------------------------
-- 4. PLAYBOOK VERSIONING COMPOSITE CONSTRAINT
-- ------------------------------------------------------------------------------
-- Ensure playbooks table allows versioning per playbook name
SET @exist := (SELECT COUNT(*) FROM information_schema.STATISTICS 
               WHERE table_schema = DATABASE() AND table_name = 'playbooks' AND index_name = 'uq_playbooks_name');
SET @drop_stmt := IF(@exist > 0, 'ALTER TABLE playbooks DROP INDEX uq_playbooks_name', 'SELECT 1');
PREPARE stmt FROM @drop_stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

ALTER TABLE playbooks
    ADD UNIQUE KEY IF NOT EXISTS uq_playbook_name_version (playbook_name, version);

SET FOREIGN_KEY_CHECKS = 1;
