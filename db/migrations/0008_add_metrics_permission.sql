-- 0008_add_metrics_permission.sql
-- Grants super_admin the ability to scrape the Prometheus /metrics endpoint.
-- Scrape pattern: mint an API token with this scope and configure Prometheus
-- to send Authorization: Bearer <token>.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

INSERT INTO permissions (key, description, category)
VALUES ('admin.system.metrics',
        'Scrape the Prometheus /metrics endpoint (HTTP request counters, latency, DB ping)',
        'admin')
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permissions (role, permission)
VALUES ('super_admin', 'admin.system.metrics')
ON CONFLICT DO NOTHING;

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (8, '0008_add_metrics_permission.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
