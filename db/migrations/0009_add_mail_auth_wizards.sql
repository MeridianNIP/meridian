-- 0009_add_mail_auth_wizards.sql
-- Two standalone mail-auth wizards complementing the existing
-- dmarc.tuning wizard. They live in the 'ddi' category for now;
-- consider renaming to a "mail-auth" category once a third member
-- (e.g. BIMI) is added.

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);

INSERT INTO wizards (key, category, name, description) VALUES
  ('spf.parser', 'ddi', 'SPF record parser',
   'Tokenises v=spf1, follows include/redirect, counts DNS lookups (RFC 7208 cap 10), flags +all/?all, lists effective senders'),
  ('dkim.parser', 'ddi', 'DKIM record parser',
   'Fetches <selector>._domainkey.<domain> TXT, parses v=DKIM1 tags, validates base64 public key, reports key bits and flags weak (<2048-bit RSA)')
ON CONFLICT (key) DO NOTHING;

INSERT INTO schema_migrations (number, filename, sha256_hex, applied_by)
VALUES (9, '0009_add_mail_auth_wizards.sql', 'pending', current_user)
ON CONFLICT (number) DO NOTHING;

COMMIT;
