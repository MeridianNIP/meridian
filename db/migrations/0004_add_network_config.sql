-- 0004_add_network_config.sql
-- Portal-editable network settings: static IP / gateway / MTU, DNS +
-- NTP + search domains, outbound proxy. One current row plus a full
-- history of applies so an admin can see who changed what and when.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

CREATE TABLE IF NOT EXISTS network_config (
  id            SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),  -- singleton
  settings      JSONB NOT NULL DEFAULT '{}'::jsonb,
  applied_at    TIMESTAMPTZ,
  applied_by    UUID REFERENCES users(id),
  apply_status  TEXT,                 -- 'ok' | 'partial' | 'failed' | NULL (never applied)
  apply_detail  JSONB,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO network_config (id, settings)
VALUES (1, '{}'::jsonb)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS network_config_history (
  id             BIGSERIAL PRIMARY KEY,
  applied_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  applied_by     UUID REFERENCES users(id),
  settings       JSONB NOT NULL,
  apply_status   TEXT NOT NULL,
  apply_detail   JSONB
);

CREATE INDEX IF NOT EXISTS ix_netcfg_history_time
  ON network_config_history (applied_at DESC);

INSERT INTO permissions (key, description, category)
VALUES ('admin.system.network',
        'View and change system network settings (IP, DNS, NTP, proxy)',
        'admin')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (role, permission)
VALUES ('super_admin', 'admin.system.network')
ON CONFLICT DO NOTHING;

-- Grant the app's DB role read/write on the new tables. Without this
-- the portal hits `permission denied for table network_config` since the
-- tables were created by `postgres` during migration.
GRANT ALL ON TABLE network_config          TO meridian;
GRANT ALL ON TABLE network_config_history  TO meridian;
GRANT USAGE, SELECT ON SEQUENCE network_config_history_id_seq TO meridian;

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (4, '0004_add_network_config.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
