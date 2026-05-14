-- 0007_add_health_auto_repair_job.sql
-- Schedule the periodic auto-repair sweep that walks every health check
-- and invokes Check.repair() for the ones marked auto_repair=True (e.g.
-- restart a stopped required service, fix 0640→0400 on a key file).
-- Destructive repairs (rebaseline, key rotation, retention cleanup)
-- carry auto_repair=False and never fire here.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

INSERT INTO jobs (name, description, cron_expression, handler, enabled)
VALUES (
  'health-auto-repair',
  'Walks every system-health check every 5 minutes; invokes any repair flagged auto_repair=True (idempotent ones — service restart, key chmod). Destructive repairs require a human in the loop and are not fired here. Audited as admin.system.repair.auto.',
  '*/5 * * * *',
  'meridian.jobs.health:auto_repair',
  TRUE
)
ON CONFLICT (name) DO NOTHING;

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (7, '0007_add_health_auto_repair_job.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
