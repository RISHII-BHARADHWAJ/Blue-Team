-- ==============================================================================
-- ThreatPulse SIEM + SOAR Platform
-- Migration: 003_playbook_approval_integrity.sql
-- Description: Adds payload_hash column to approval_requests for tamper-detection
--              and step_results table for per-step execution logging.
-- NON-DESTRUCTIVE & ADDITIVE: existing SIEM tables untouched.
-- ==============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- Add payload_hash to approval_requests for approval integrity verification
ALTER TABLE approval_requests
    ADD COLUMN IF NOT EXISTS payload_hash VARCHAR(64) NULL COMMENT 'SHA-256 hash of action_payload at time of request creation'
    AFTER action_payload;

-- Step execution log: one record per step attempt within a playbook run
CREATE TABLE IF NOT EXISTS playbook_step_results (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    playbook_run_id BIGINT UNSIGNED NOT NULL,
    step_id BIGINT UNSIGNED NOT NULL,
    step_order INT UNSIGNED NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    attempt_number TINYINT UNSIGNED NOT NULL DEFAULT 1,
    status ENUM('SUCCESS','FAILED','SKIPPED','WAITING_APPROVAL','TIMED_OUT') NOT NULL,
    started_at DATETIME NOT NULL,
    completed_at DATETIME NULL,
    output JSON NULL,
    error_message TEXT NULL,
    is_dry_run BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT fk_step_results_run FOREIGN KEY (playbook_run_id) REFERENCES playbook_runs(id) ON DELETE CASCADE,
    CONSTRAINT fk_step_results_step FOREIGN KEY (step_id) REFERENCES playbook_steps(id) ON DELETE CASCADE,

    INDEX idx_step_results_run (playbook_run_id),
    INDEX idx_step_results_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
