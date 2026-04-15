-- Add attempt_count column to mfa_pending_sessions for retry limiting
ALTER TABLE mfa_pending_sessions ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;
