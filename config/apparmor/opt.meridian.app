# Meridian · AppArmor profile for the application worker
# Installed to /etc/apparmor.d/opt.meridian.app by install.sh.
# Enforced via:  aa-enforce /etc/apparmor.d/opt.meridian.app
#
# Scope: confines the gunicorn-hosted FastAPI process. It has DB access
# via a local socket, read-only access to the app tree, read-write to
# the data/log dirs and the secrets dir, and no ability to load arbitrary
# shared libs outside the venv.

#include <tunables/global>

/opt/meridian/venv/bin/python {
    #include <abstractions/base>
    #include <abstractions/python>
    #include <abstractions/nameservice>
    #include <abstractions/ssl_certs>

    # Network: client-only to localhost services (Postgres, Redis, Bind9)
    network inet stream,
    network inet6 stream,
    network inet dgram,
    network inet6 dgram,
    network netlink raw,

    # Binaries
    /opt/meridian/venv/bin/python            mr,
    /opt/meridian/venv/bin/gunicorn          mr,
    /opt/meridian/venv/bin/celery            mr,
    /opt/meridian/venv/bin/uvicorn           mr,
    /usr/bin/python3                         mr,

    # App tree (read-only)
    /opt/meridian/**                         r,
    /opt/meridian/app/**                     r,
    /opt/meridian/venv/**                    mr,

    # Config
    /etc/meridian/**                         r,
    /etc/meridian/secrets/**                 r,
    /etc/ssl/certs/**                        r,

    # Data + logs (read-write)
    /var/lib/meridian/**                     rwk,
    /var/log/meridian/**                     rwk,

    # Runtime state
    /run/meridian/**                         rwk,
    /proc/sys/kernel/random/uuid             r,
    /proc/*/stat                             r,
    /proc/*/status                           r,
    /proc/loadavg                            r,
    /proc/cpuinfo                            r,
    /proc/meminfo                            r,

    # Tool binaries the sandbox may invoke
    /usr/bin/dig                             ixr,
    /usr/bin/host                            ixr,
    /usr/bin/whois                           ixr,
    /usr/bin/curl                            ixr,
    /usr/bin/ping                            ixr,
    /usr/bin/ping6                           ixr,
    /usr/bin/traceroute                      ixr,
    /usr/sbin/mtr                            ixr,
    /usr/bin/nmap                            ixr,
    /usr/bin/snmpwalk                        ixr,
    /usr/bin/snmpget                         ixr,
    /usr/sbin/tcpdump                        Cx,

    # Denied
    deny /etc/shadow                         r,
    deny /root/**                            r,
    deny capability sys_module,
    deny capability sys_rawio,
    deny capability sys_ptrace,
    deny capability sys_boot,
    deny capability dac_override,
}
