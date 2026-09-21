-- ==============================================================================
-- ThreatPulse SIEM + SOAR Platform
-- Migration: 004_playbook_execution_cursor.sql
-- Description: Adds schema support for precise execution cursor tracking and
--              step idempotency enforcement.
--
-- Changes:
--   1. Adds a unique constraint on playbook_step_results(playbook_run_id,
--      step_order, attempt_number) to prevent duplicate attempt records.
--      NOTE: Multiple attempts ARE allowed (failed attempt 1, retry attempt 2).
--      The uniqueness prevents the SAME attempt being recorded twice.
--
--   2. Confirms that playbook_runs.current_step_order already exists from
--      Migration 001 and documents its semantics as the execution cursor.
--
-- Idempotency guarantee:
--   The application-level findSuccessfulStepResult() query enforces that a
--   step with status='SUCCESS' cannot be re-executed. This constraint prevents
--   the same attempt number being stored twice at the DB level.
--
-- NON-DESTRUCTIVE & ADDITIVE: no existing data is modified.
-- ==============================================================================

SET FOREIGN_KEY_CHECKS = 0;

-- Add unique constraint to prevent duplicate (run_id, step_order, attempt_number) records.
-- This prevents accidental double-recording of the same execution attempt.
-- Multiple rows ARE valid for the same (run_id, step_order) with different attempt_numbers.
ALTER TABLE playbook_step_results
    ADD CONSTRAINT IF NOT EXISTS uq_step_result_attempt
        UNIQUE (playbook_run_id, step_order, attempt_number);

-- Document the semantics of current_step_order as an execution cursor.
-- This column already exists from migration 001 (default = 1).
-- Semantics enforced by PlaybookEngine:
--   - Set to the step_order of the step CURRENTLY BEING EXECUTED.
--   - Remains at the paused step when status = 'WAITING_APPROVAL'.
--   - Advanced to the NEXT step AFTER successful completion.
--   - PlaybookEngine::resumeAfterApproval() reads this cursor to resume
--     exactly at the right step without re-running prior completed steps.
-- No schema change needed; column already present.

SET FOREIGN_KEY_CHECKS = 1;
