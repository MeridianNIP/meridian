-- 0011_lockout_appeals.sql
-- Captures "I'm locked out, please help" submissions from the public
-- /ui/locked-out page. Each row is rate-limited at the app layer to one
-- per IP per hour. Admins review them via /ui/admin/users (filter on
-- locked = true) or directly via SQL.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

CREATE TABLE IF NOT EXISTS lockout_appeals (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  source_ip       INET,
  user_agent      TEXT,
  -- Either an existing username or a free-form "what I'm trying to log in as".
  -- Untrusted user input; render escaped.
  claimed_username TEXT,
  -- Email the user wants the admin to reach them at. May or may not match a
  -- known user row. Untrusted.
  contact_email   TEXT,
  context         TEXT,        -- free-form "what happened"
  status          TEXT NOT NULL DEFAULT 'open',  -- open | resolved | spam
  resolved_at     TIMESTAMPTZ,
  resolved_by     UUID REFERENCES users(id),
  resolved_note   TEXT
);

CREATE INDEX IF NOT EXISTS ix_lockout_appeals_open
  ON lockout_appeals (submitted_at DESC)
  WHERE status = 'open';

GRANT ALL ON TABLE lockout_appeals TO meridian;

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (11, '0011_lockout_appeals.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
