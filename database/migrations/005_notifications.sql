-- ==============================================================================
-- ThreatPulse SIEM + SOAR Platform
-- Migration: 005_notifications.sql
-- Description: Creates the notification schema and extends approvals/playbooks
--              for Phase 7 SOC Approval & Response Control Plane.
--
-- NON-DESTRUCTIVE & ADDITIVE:
--   - Enhances notifications table with type, approval_id, playbook_run_id, read_at
--   - Extends approval_requests status with 'CANCELLED' and adds decided_at
--   - Adds playbook_version tracking to playbook_runs
--   - Updates playbooks uniqueness constraint to (playbook_name, version)
--   - Preserves all existing SIEM tables (logs, ip_geo, users, audit_log, rate_limits)
-- ==============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ------------------------------------------------------------------------------
-- 1. NOTIFICATIONS TABLE ENHANCEMENT
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    recipient_id INT NOT NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'APPROVAL_REQUIRED',
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    approval_id BIGINT UNSIGNED NULL,
    playbook_run_id BIGINT UNSIGNED NULL,
    read_at DATETIME NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_notifications_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_notifications_incident FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,

    INDEX idx_notifications_user_read (user_id, is_read),
    INDEX idx_notifications_type (type),
    INDEX idx_notifications_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add any missing columns to existing notifications table if created in Migration 001
ALTER TABLE notifications
    ADD COLUMN IF NOT EXISTS user_id INT NOT NULL DEFAULT 1 AFTER id,
    ADD COLUMN IF NOT EXISTS type VARCHAR(50) NOT NULL DEFAULT 'APPROVAL_REQUIRED' AFTER recipient_id,
    ADD COLUMN IF NOT EXISTS approval_id BIGINT UNSIGNED NULL AFTER incident_id,
    ADD COLUMN IF NOT EXISTS playbook_run_id BIGINT UNSIGNED NULL AFTER approval_id,
    ADD COLUMN IF NOT EXISTS read_at DATETIME NULL AFTER is_read;

-- ------------------------------------------------------------------------------
-- 2. APPROVAL_REQUESTS EXTENSIONS
-- ------------------------------------------------------------------------------
-- Support CANCELLED status in approval state machine and record decision timestamp
ALTER TABLE approval_requests
    MODIFY COLUMN status ENUM('PENDING','APPROVED','REJECTED','EXPIRED','CANCELLED') NOT NULL DEFAULT 'PENDING',
    ADD COLUMN IF NOT EXISTS decided_at DATETIME NULL AFTER reviewed_at;

-- ------------------------------------------------------------------------------
-- 3. PLAYBOOK RUNS VERSION TRACKING
-- ------------------------------------------------------------------------------
-- Lock active playbook runs to the specific playbook definition version
ALTER TABLE playbook_runs
    ADD COLUMN IF NOT EXISTS playbook_version INT UNSIGNED NOT NULL DEFAULT 1 AFTER playbook_id;

-- ------------------------------------------------------------------------------
-- 4. PLAYBOOK VERSIONING CONSTRAINT
-- ------------------------------------------------------------------------------
-- Update unique constraint from (playbook_name) to (playbook_name, version)
-- so new immutable versions can be published for the same playbook name.
-- In MySQL/MariaDB, drop existing unique index if exists, then add composite unique key.
SET @exist := (SELECT COUNT(*) FROM information_schema.STATISTICS 
               WHERE table_schema = DATABASE() AND table_name = 'playbooks' AND index_name = 'uq_playbooks_name');
SET @drop_stmt := IF(@exist > 0, 'ALTER TABLE playbooks DROP INDEX uq_playbooks_name', 'SELECT 1');
PREPARE stmt FROM @drop_stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

ALTER TABLE playbooks
    ADD UNIQUE KEY IF NOT EXISTS uq_playbook_name_version (playbook_name, version);

SET FOREIGN_KEY_CHECKS = 1;
