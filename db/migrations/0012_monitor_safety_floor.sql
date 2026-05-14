-- 0012_monitor_safety_floor.sql
-- Backstop the monitor interval floor at the database layer. The form
-- validator already clamps to 30–3600 s; the collector clamps again at
-- runtime; this constraint stops an admin (or a buggy migration) from
-- writing a row that would, in another universe, hammer a target every
-- second. Defence in depth per project_meridian_safety_caps.md.
--
-- See `app/safety/limits.py`:
--   MONITOR_INTERVAL_FLOOR_S   = 30
--   MONITOR_INTERVAL_CEILING_S = 3600
-- Keep those constants and this constraint in sync.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL,
  sha256_hex   TEXT NOT NULL,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  applied_by   TEXT NOT NULL
);

-- The constraint is added NOT VALID first so a single bad existing row
-- (if any) doesn't block the migration; then VALIDATE in a separate
-- statement so future inserts/updates are blocked. Existing rows that
-- violate are repaired by the UPDATE above the VALIDATE.

-- Repair: clamp any out-of-range rows to the floor / ceiling.
UPDATE monitors SET interval_seconds = 30   WHERE interval_seconds < 30;
UPDATE monitors SET interval_seconds = 3600 WHERE interval_seconds > 3600;

ALTER TABLE monitors
  ADD CONSTRAINT monitors_interval_safety
  CHECK (interval_seconds >= 30 AND interval_seconds <= 3600);

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (12, '0012_monitor_safety_floor.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
