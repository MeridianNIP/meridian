# Meridian · schema migrations

`schema.sql` is the **fresh-install** schema. It's the canonical source of
truth for a brand-new database and gets loaded verbatim by `install.sh` on a
clean install.

Once a customer is running a tagged release, any further schema change MUST
ship as a numbered file in this directory. At upgrade time, `install.sh`
(or `scripts/meridian-nip migrate`) applies every file whose number is
greater than the highest `schema_migrations.number` recorded in the DB.

## Filename convention

```
0001_add_network_devices.sql
0002_rename_something.sql
0003_backfill_foo.sql
```

Four-digit zero-padded number, underscore, snake-case description, `.sql`.
Numbers are unique and monotonic — never reuse one, never reorder.

## File structure

Each file must be idempotent where reasonable (`IF NOT EXISTS`, `CREATE OR
REPLACE`) and wrapped so a partial failure rolls back cleanly:

```sql
-- 0001_add_network_devices.sql
-- Adds the tables + enum that back the Network Devices admin tab.
-- Equivalent to the corresponding block in schema.sql §28b.

BEGIN;

CREATE TYPE device_kind AS ENUM (...);

CREATE TABLE network_devices ( ... );
CREATE TABLE device_config_snapshots ( ... );
CREATE TABLE device_backup_runs ( ... );

INSERT INTO permissions (key, description, category, requires_two_person) VALUES
  ('admin.devices.view', ...),
  ('admin.devices.manage', ...);

INSERT INTO jobs (name, description, cron_expression, handler, enabled) VALUES
  ('device-config-backup', ...),
  ('device-retention', ...);

COMMIT;
```

## Migration runner

The `schema_migrations` table is created by migration 0001 if missing:

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
  number       INTEGER PRIMARY KEY,
  filename     TEXT NOT NULL UNIQUE,
  applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sha256_hex   TEXT NOT NULL,
  applied_by   TEXT
);
```

`scripts/migrate.sh` is the portable runner: it enumerates
`db/migrations/*.sql` in order, checks each against `schema_migrations`, and
applies the new ones inside a transaction. Hash is recorded so an
accidentally-edited-after-apply file produces a loud error on the next run.

## Never do this

- **Don't edit a migration that's already applied** anywhere — the hash
  mismatch will trip `migrate.sh` and refuse to run. Instead, write a new
  migration that corrects whatever went wrong.
- **Don't edit `schema.sql` in place and expect existing installs to pick
  up the change.** `schema.sql` is fresh-install only. If the change matters
  to existing users, it needs a migration file too.
- **Don't skip numbers.** The runner assumes a contiguous sequence.
