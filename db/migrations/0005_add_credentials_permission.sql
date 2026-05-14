-- 0005_add_credentials_permission.sql
-- Grants super_admin the ability to rotate built-in credentials
-- (portal admin, Linux accounts, DB role, keys, SSH host keys).

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

INSERT INTO permissions (key, description, category)
VALUES ('admin.system.credentials',
        'Rotate portal admin, Linux, DB, and cryptographic key credentials',
        'admin')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (role, permission)
VALUES ('super_admin', 'admin.system.credentials')
ON CONFLICT DO NOTHING;

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (5, '0005_add_credentials_permission.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
