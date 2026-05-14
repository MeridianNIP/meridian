# Meridian · config templates

Every file in this directory is placed on a Meridian host by `install.sh`.
Templates (`*.template`) contain `${VAR}`-style placeholders substituted at
install time via `envsubst`; plain files are copied verbatim.

| Source (repo)                                    | Rendered to (host)                                            |
|--------------------------------------------------|---------------------------------------------------------------|
| `nginx.conf.template`                            | `/etc/nginx/sites-available/meridian`                         |
| `nginx.snippets.meridian_proxy.conf`             | `/etc/nginx/snippets/meridian_proxy.conf`                     |
| `bind9/named.conf.template`                      | `/etc/bind/named.conf.local`                                  |
| `systemd/meridian-app.service.template`          | `/etc/systemd/system/meridian-app.service`                    |
| `systemd/meridian-celery.service.template`       | `/etc/systemd/system/meridian-celery.service`                 |
| `systemd/meridian-beat.service.template`         | `/etc/systemd/system/meridian-beat.service`                   |
| `fail2ban/jail.meridian.conf`                    | `/etc/fail2ban/jail.d/meridian.conf`                          |
| `fail2ban/filter.d/meridian-login.conf`          | `/etc/fail2ban/filter.d/meridian-login.conf`                  |
| `apparmor/opt.meridian.app`                      | `/etc/apparmor.d/opt.meridian.app`                            |
| `logrotate/meridian`                             | `/etc/logrotate.d/meridian`                                   |
| `sysctl.d/99-meridian.conf`                      | `/etc/sysctl.d/99-meridian.conf`                              |
| `postgresql/postgresql.conf.overlay`             | `/etc/postgresql/15/main/conf.d/meridian.conf`                |
| `ssh/sshd_config.d.meridian.conf.template`       | `/etc/ssh/sshd_config.d/10-meridian.conf`                     |
| `ufw/meridian.rules.template`                    | executed by install.sh (not a persistent file)                |
| `redis/redis.conf.overlay`                       | appended to `/etc/redis/redis.conf` (Debian 12 only)          |
| `valkey/valkey.conf.overlay`                     | appended to `/etc/valkey/valkey.conf` (Debian 13 only)        |

## Variables available to templates

| Name              | Meaning                                                |
|-------------------|--------------------------------------------------------|
| `PORTAL_DOMAIN`   | Primary FQDN chosen at install                         |
| `PORTAL_NAME`     | Customer display name (from branding)                  |
| `SSH_PORT`        | Chosen SSH listen port                                 |
| `SSH_GROUP`       | Unix group permitted SSH login (`ddi-ssh`)             |
| `SVC_USER`        | Service user (`meridian`)                              |
| `SVC_GROUP`       | Service group (`meridian`)                             |
| `INSTALL_ROOT`    | `/opt/meridian`                                        |
| `CONFIG_ROOT`     | `/etc/meridian`                                        |
| `DATA_ROOT`       | `/var/lib/meridian`                                    |
| `LOG_ROOT`        | `/var/log/meridian`                                    |
| `SCOPE_OF_USE`    | `internal` / `external` / `both`                       |
| `TIMEZONE`        | Chosen default timezone                                |

## Editing rules

- Never hardcode a customer value. Use a template variable.
- Every toggle / gate / feature flag must include a one-line description.
- Templates must produce valid output when all variables are empty-safe
  (the installer validates before rendering; missing required vars fail fast).
- Place the license text for any vendored snippet at the top as a comment.
