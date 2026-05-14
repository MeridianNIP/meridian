-- 0013_branding_monitors_schema_drift.sql
--
-- Catches up the live `branding` and `monitors` tables to the columns
-- the SQLAlchemy models in app/models/branding.py + app/models/monitor.py
-- have declared. Without this migration:
--   - GET /ui/admin/branding fails with "column branding.password_min_length does not exist"
--   - GET /ui/monitors      fails with "column monitors.fail_threshold does not exist"
--
-- Schema-drift caught 2026-05-13 during the unattended-rebuild
-- validation pass. The model grew over time; schema.sql + earlier
-- migrations never got the corresponding ALTERs. schema.sql is also
-- updated in this PR so fresh installs get the columns at create time
-- without needing this migration.

BEGIN;

-- ---------------------------------------------------------------------------
-- branding: policy fields the admin settings page reads
-- ---------------------------------------------------------------------------
ALTER TABLE branding
  ADD COLUMN IF NOT EXISTS password_min_length         INTEGER NOT NULL DEFAULT 12,
  ADD COLUMN IF NOT EXISTS password_required_classes   INTEGER NOT NULL DEFAULT 3,
  ADD COLUMN IF NOT EXISTS password_max_age_days       INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS password_history_depth      INTEGER NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS mfa_requirement             TEXT    NOT NULL DEFAULT 'admins_only',
  ADD COLUMN IF NOT EXISTS mfa_allowed_methods         TEXT[]  NOT NULL DEFAULT ARRAY['totp','webauthn','backup_codes'],
  ADD COLUMN IF NOT EXISTS mfa_backup_codes_count      INTEGER NOT NULL DEFAULT 10,
  ADD COLUMN IF NOT EXISTS lockout_threshold           INTEGER NOT NULL DEFAULT 5,
  ADD COLUMN IF NOT EXISTS lockout_duration_min        INTEGER NOT NULL DEFAULT 30,
  ADD COLUMN IF NOT EXISTS lockout_unlock_mode         TEXT    NOT NULL DEFAULT 'admin_or_time',
  ADD COLUMN IF NOT EXISTS audit_online_days           INTEGER NOT NULL DEFAULT 365,
  ADD COLUMN IF NOT EXISTS audit_archive_days          INTEGER NOT NULL DEFAULT 2555,
  ADD COLUMN IF NOT EXISTS audit_archive_target        TEXT    NOT NULL DEFAULT 'local';

-- ---------------------------------------------------------------------------
-- monitors: notification policy fields the monitors page + dispatcher read
-- ---------------------------------------------------------------------------
ALTER TABLE monitors
  ADD COLUMN IF NOT EXISTS fail_threshold        INTEGER NOT NULL DEFAULT 3,
  ADD COLUMN IF NOT EXISTS recovery_notify       BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS quiet_hours_start     INTEGER,
  ADD COLUMN IF NOT EXISTS quiet_hours_end       INTEGER,
  ADD COLUMN IF NOT EXISTS renotify_interval_min INTEGER;

-- Defensive: clamp fail_threshold to a sane range so an admin editing
-- the row directly can't set 0 or absurdly large values.
-- PG doesn't support ADD CONSTRAINT IF NOT EXISTS, so guard manually.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'monitors_fail_threshold_safe') THEN
    ALTER TABLE monitors
      ADD CONSTRAINT monitors_fail_threshold_safe
      CHECK (fail_threshold >= 1 AND fail_threshold <= 20);
  END IF;
END
$$;

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (13, '0013_branding_monitors_schema_drift.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
