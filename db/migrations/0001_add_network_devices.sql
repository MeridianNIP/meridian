-- 0001_add_network_devices.sql
-- Adds the Network Devices subsystem (tables, enum, permissions, scheduled
-- jobs) to an existing install. Equivalent to schema.sql §28b + permission
-- seeds + two entries in the jobs table.

BEGIN;

-- Migration bookkeeping. Idempotent — survives a partial first run.
CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

DO $mig$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'device_kind') THEN
    CREATE TYPE device_kind AS ENUM (
      'cisco_ios','cisco_iosxr','cisco_nxos','cisco_asa',
      'juniper_junos','arista_eos',
      'palo_alto','fortinet','mikrotik','generic_ssh'
    );
  END IF;
END $mig$;

CREATE TABLE IF NOT EXISTS network_devices (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name               TEXT NOT NULL UNIQUE,
  description        TEXT,
  kind               device_kind NOT NULL,
  mgmt_host          TEXT NOT NULL,
  mgmt_port          INTEGER NOT NULL DEFAULT 22,
  username           TEXT,
  secret_id          UUID REFERENCES secrets(id),
  enable_secret_id   UUID REFERENCES secrets(id),
  enabled            BOOLEAN NOT NULL DEFAULT TRUE,
  auto_backup        BOOLEAN NOT NULL DEFAULT TRUE,
  tags               TEXT[] NOT NULL DEFAULT '{}',
  site               TEXT,
  last_backup_at     TIMESTAMPTZ,
  last_backup_ok     BOOLEAN,
  last_backup_error  TEXT,
  last_config_sha256 TEXT,
  config             JSONB NOT NULL DEFAULT '{}',
  created_by         UUID REFERENCES users(id),
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_devices_enabled ON network_devices (enabled, auto_backup);
DROP TRIGGER IF EXISTS tg_devices_touch ON network_devices;
CREATE TRIGGER tg_devices_touch BEFORE UPDATE ON network_devices
  FOR EACH ROW EXECUTE FUNCTION fn_touch_updated_at();

CREATE TABLE IF NOT EXISTS device_config_snapshots (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id          UUID NOT NULL REFERENCES network_devices(id) ON DELETE CASCADE,
  ts                 TIMESTAMPTZ NOT NULL DEFAULT now(),
  trigger_kind       TEXT NOT NULL,
  raw_config         TEXT NOT NULL,
  size_bytes         INTEGER NOT NULL,
  sha256_hex         TEXT NOT NULL,
  line_count         INTEGER,
  prev_snapshot_id   UUID REFERENCES device_config_snapshots(id),
  diff_from_prev     TEXT,
  diff_lines_added   INTEGER,
  diff_lines_removed INTEGER,
  captured_by        UUID REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS ix_snap_device_ts ON device_config_snapshots (device_id, ts DESC);

CREATE TABLE IF NOT EXISTS device_backup_runs (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at       TIMESTAMPTZ,
  trigger_kind       TEXT NOT NULL,
  devices_attempted  INTEGER NOT NULL DEFAULT 0,
  devices_ok         INTEGER NOT NULL DEFAULT 0,
  devices_changed    INTEGER NOT NULL DEFAULT 0,
  devices_failed     INTEGER NOT NULL DEFAULT 0,
  status             TEXT NOT NULL DEFAULT 'running'
);
CREATE INDEX IF NOT EXISTS ix_device_runs_started ON device_backup_runs (started_at DESC);

-- Permissions
INSERT INTO permissions (key, description, category, requires_two_person) VALUES
  ('admin.devices.view',   'Read network device inventory, config snapshots, and diffs',                           'admin', FALSE),
  ('admin.devices.manage', 'Add / edit / remove network devices, rotate credentials, trigger backups',             'admin', TRUE)
ON CONFLICT (key) DO NOTHING;

-- super_admin gets every permission
INSERT INTO role_permissions (role, permission)
SELECT 'super_admin', key FROM permissions WHERE key IN ('admin.devices.view','admin.devices.manage')
ON CONFLICT DO NOTHING;

-- admin gets the read permission by default; manage is granted per group
INSERT INTO role_permissions (role, permission)
SELECT 'admin', 'admin.devices.view'
ON CONFLICT DO NOTHING;

-- Scheduled jobs
INSERT INTO jobs (name, description, cron_expression, handler, enabled) VALUES
  ('device-config-backup',
   'Pull running-config from every enabled network device; stores on SHA change only',
   '0 3 * * *', 'meridian.jobs.devices:backup_all', TRUE),
  ('device-retention',
   'Trim device config snapshots per retention_rules.scope = device_snapshots',
   '0 5 * * *', 'meridian.jobs.devices:retention', TRUE)
ON CONFLICT (name) DO NOTHING;

COMMIT;
