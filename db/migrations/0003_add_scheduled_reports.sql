-- 0003_add_scheduled_reports.sql
-- Scheduled Reports subsystem: recurring report generation with
-- download + email delivery. Adds two tables, one permission, no
-- seed data.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

CREATE TABLE IF NOT EXISTS report_schedules (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id              UUID REFERENCES users(id) ON DELETE SET NULL,
  name                  TEXT NOT NULL,
  report_type           TEXT NOT NULL,
  cadence               TEXT NOT NULL DEFAULT 'daily',
  cron_expression       TEXT NOT NULL,
  timezone_name         TEXT NOT NULL DEFAULT 'UTC',
  format                TEXT NOT NULL DEFAULT 'csv',
  delivery              TEXT NOT NULL DEFAULT 'download',
  email_to              TEXT,
  filters               JSONB NOT NULL DEFAULT '{}'::jsonb,
  enabled               BOOLEAN NOT NULL DEFAULT TRUE,
  last_run_at           TIMESTAMPTZ,
  next_run_at           TIMESTAMPTZ,
  consecutive_failures  INTEGER NOT NULL DEFAULT 0,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT ck_report_schedules_cadence   CHECK (cadence IN ('daily','weekly','monthly','custom')),
  CONSTRAINT ck_report_schedules_format    CHECK (format IN ('csv','html')),
  CONSTRAINT ck_report_schedules_delivery  CHECK (delivery IN ('download','email'))
);

CREATE INDEX IF NOT EXISTS ix_report_schedules_next_run_at
  ON report_schedules(next_run_at)
  WHERE enabled = TRUE;

CREATE TABLE IF NOT EXISTS report_runs (
  id               BIGSERIAL PRIMARY KEY,
  schedule_id      UUID REFERENCES report_schedules(id) ON DELETE SET NULL,
  triggered_by     UUID REFERENCES users(id) ON DELETE SET NULL,
  report_type      TEXT NOT NULL,
  format           TEXT NOT NULL,
  started_at       TIMESTAMPTZ NOT NULL,
  finished_at      TIMESTAMPTZ,
  status           TEXT NOT NULL DEFAULT 'running',
  artifact_path    TEXT,
  artifact_bytes   BIGINT,
  row_count        INTEGER,
  detail           JSONB,
  CONSTRAINT ck_report_runs_status CHECK (status IN ('running','success','failed'))
);

CREATE INDEX IF NOT EXISTS ix_report_runs_schedule_started
  ON report_runs(schedule_id, started_at DESC);

CREATE INDEX IF NOT EXISTS ix_report_runs_started
  ON report_runs(started_at DESC);

-- Permission seed so the UI can gate the Reports tab. Admins and
-- operators can schedule; viewers can only see runs.
INSERT INTO permissions (key, description, category)
VALUES ('reports.schedule', 'Create, edit, and run scheduled reports', 'admin')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (role, permission)
VALUES
  ('super_admin', 'reports.schedule'),
  ('admin',       'reports.schedule'),
  ('analyst',     'reports.schedule')
ON CONFLICT DO NOTHING;

-- Fail2ban management (super_admin only — whitelisting touches the
-- security perimeter, so the broader admin role is intentionally kept out).
INSERT INTO permissions (key, description, category)
VALUES ('admin.system.fail2ban',
        'View/unban IPs and manage ignore lists in fail2ban',
        'admin')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (role, permission)
VALUES ('super_admin', 'admin.system.fail2ban')
ON CONFLICT DO NOTHING;

-- Grant the app's DB role access to the new tables. Migrations run as
-- `postgres`, which leaves the tables inaccessible to the meridian role
-- that the portal connects with.
GRANT ALL ON TABLE report_schedules  TO meridian;
GRANT ALL ON TABLE report_runs       TO meridian;
GRANT USAGE, SELECT ON SEQUENCE report_runs_id_seq TO meridian;

-- Register the beat tick so the scheduler picks up new schedules.
INSERT INTO jobs (name, description, cron_expression, handler, enabled)
VALUES (
  'reports-tick',
  'Scans enabled report_schedules every minute and fires due runs · scheduled reports subsystem',
  '* * * * *',
  'meridian.jobs.reports:tick',
  TRUE
)
ON CONFLICT (name) DO NOTHING;

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (3, '0003_add_scheduled_reports.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
