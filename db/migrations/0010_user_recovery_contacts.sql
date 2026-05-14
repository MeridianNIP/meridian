-- 0010_user_recovery_contacts.sql
-- Adds secondary recovery contact channels (email + phone) to the users
-- table. The password-reset / lockout-recovery flow already exists; once
-- the primary email channel fails (e.g. corporate mailbox decommissioned
-- the same day the laptop walks off), the recovery_email / recovery_phone
-- columns give the operator an out-of-band way to reach the user.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS recovery_email TEXT,
  ADD COLUMN IF NOT EXISTS recovery_phone TEXT;

COMMENT ON COLUMN users.recovery_email IS
  'Secondary email address used by the password-reset / lockout flow when the primary mailbox is unreachable. NULL = none configured.';
COMMENT ON COLUMN users.recovery_phone IS
  'Secondary phone (E.164, e.g. +15555550100) used by lockout SMS flow. NULL = none configured. SMS provider integration is a follow-up.';

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (10, '0010_user_recovery_contacts.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
