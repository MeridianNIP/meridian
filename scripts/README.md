# Meridian · operator scripts

Runtime helpers shipped with the Meridian package. All are installed to
`/opt/meridian/scripts/` by `install.sh`. The CLI shim is linked into
`/usr/local/bin/meridian-nip` so operators can invoke it from anywhere.

| Script              | Purpose                                                    | Runs as   |
|---------------------|------------------------------------------------------------|-----------|
| `meridian-nip`      | Shim into the app's Click CLI (users, license, doctor, …)  | any user  |
| `doctor.sh`         | Friendly pre-flight / environment check                    | any user  |
| `health_check.sh`   | One-shot health status (exit 0 = healthy, `--json` mode)   | any user  |
| `backup.sh`         | Full backup (pg_dump + config + uploads + optional keys)   | root      |
| `restore.sh`        | Restore from a `backup.sh` bundle                          | root      |
| `wal_archive.sh`    | PostgreSQL `archive_command` hook (WAL shipping)           | postgres  |
| `setup_luks.sh`     | Interactive LUKS volume setup for `/var/lib/postgresql`    | root      |

## Conventions

- `set -euo pipefail` at the top of every script.
- Coloured output uses a tight set of helpers so the tone matches `install.sh`.
- Destructive operations (setup_luks, restore) require a typed confirmation
  string, not just y/N.
- `--dry-run` is honored where the op would make changes; it proves the
  bundle is readable / the targets are writable without touching anything.
- External-facing return codes: `0` healthy / completed, non-zero = problem.
- All timestamps emitted are UTC ISO-8601 (matches audit log format).

## Related scheduled jobs

The following Celery jobs invoke some of these scripts:

| Job                  | Calls                                       |
|----------------------|---------------------------------------------|
| `db-full-backup`     | `backup.sh` (no `--include-keys`)           |
| `db-wal-ship`        | (implicit: WAL archive fires `wal_archive.sh` per-segment) |
| `db-integrity-scan`  | Python-side; no script equivalent          |
