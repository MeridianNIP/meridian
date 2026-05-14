# CLI tools on the Meridian host

Admins SSH'd into a Meridian install can reproduce every portal feature from
the shell with the tools below. Each entry covers **what it is**, **when to
reach for it**, and **one example** of the most common invocation. All of
these are installed automatically by `install.sh`.

> **Heads-up**: Meridian's own DNS recursor runs on 127.0.0.1 (BIND9). Most
> `dig` / mail-auth tools below default to that resolver so results match
> what the portal sees. Point at `8.8.8.8` or your upstream if you need a
> view from outside.

## DNS — lookups and zone admin

### `dig`
Authoritative DNS query tool. Used for portal parity with the **DNS Tools**
section.
```
dig +short MX example.com
dig @127.0.0.1 TXT _dmarc.example.com +short
dig +trace example.com           # full delegation path
```

### `host` / `nslookup`
Alternative DNS lookup front-ends; same data, different output style.
```
host example.com
```

### `whois`
Registrar / handle lookups. Mirrors the portal's **Domain info** card.
```
whois example.com | grep -E '(Registrar|Expir|Name Server)'
```

### `rndc`
Talks to the local BIND9 daemon. Mirrors the portal's **DNS → Recursor**
health + cache controls.
```
rndc status                      # daemon health, zones, threads
rndc flush                       # clear the recursive cache
rndc reload                      # re-read zones (if any are defined)
```

### `named-checkconf` / `named-checkzone`
Validate BIND config or zone files before reloading — saves a broken
recursor.
```
named-checkconf /etc/bind/named.conf
named-checkzone example.com /etc/bind/db.example.com
```

## DNSSEC — validate, trace, flush bad cache

When a zone's DNSSEC answers differ between the outside world and what
Meridian's recursor has cached (e.g. a DS rollover went bad and your
cache is now serving the old chain), the workflow is: **probe → diagnose
→ flush**.

### `delv`
BIND's DNSSEC-validating lookup tool. Same answer `dig` would give, but
also walks the chain of trust and reports `fully validated`,
`unsigned`, or a specific validation error.
```
delv @127.0.0.1 example.com +multi
delv @8.8.8.8   example.com +rtrace    # compare upstream vs local
```

### `drill -TD`
ldns-based DNSSEC trace. Prints every signed RRSet from root down to the
name you asked for, which is useful when you need to see *exactly* which
link in the chain is broken.
```
drill -TD example.com              # full DNSSEC trust trace
ldns-verify-zone -V5 db.example.com # verify a local zone file's signatures
```

### `dnsviz`
Command-line equivalent of [dnsviz.net](https://dnsviz.net). Probes a
domain, renders the chain, and tells you exactly which DS/DNSKEY pair is
broken, missing, or expired. Generates a text summary or an SVG diagram.
```
dnsviz probe example.com > probe.json
dnsviz print  probe.json           # human-readable status
dnsviz graph  probe.json -o example.svg -T svg   # SVG of the chain
dnsviz grok   probe.json           # errors/warnings only, terse
```
Pipe them together for a one-shot diagnose:
```
dnsviz probe example.com | dnsviz grok
```

### Flushing bad cached DNSSEC data
When your resolver has cached a bad signature and upstream now serves a
good one, flush surgically — don't nuke the whole cache unless you must.
```
rndc flushname example.com         # flush exactly one name
rndc flushtree example.com         # flush this name AND every subdomain
rndc flush                         # nuclear option: whole recursor cache
```
After flushing, re-query with `+cd` (checking-disabled) off to make the
resolver re-fetch and re-validate:
```
dig +dnssec example.com A           # ad flag should be set if valid
```

## Mail auth — SPF / DKIM / DMARC

### `spfquery`
SPF evaluator (`spf-tools-perl`). Meridian's **Mail auth monitor** runs the
same check under the hood.
```
spfquery --ip 203.0.113.1 --mfrom postmaster@example.com --helo mx.example.com
# result: pass | fail | softfail | neutral | none | permerror | temperror
```
To just read the raw SPF TXT (no evaluation):
```
dig +short TXT example.com | grep 'v=spf1'
```

### `opendkim-testkey`
Verifies a DKIM selector is reachable in DNS **and** that the private key on
disk matches the published public key. Mirrors the portal's **DKIM key
validator** wizard.
```
opendkim-testkey -d example.com -s mailer -k /etc/dkim/mailer.private -vvv
```

### `opendkim-testmsg`
Verifies the DKIM signature on an RFC-822 message file — feed it the raw
email bytes (headers + body).
```
opendkim-testmsg < /tmp/suspect.eml
```

### DMARC — no dedicated tool, just TXT lookup
Meridian's DMARC monitor resolves the `_dmarc.<domain>` TXT record and
parses it. From the shell:
```
dig +short TXT _dmarc.example.com
# expect: "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; ..."
```

### `swaks`
SMTP Swiss Army Knife. Used by the portal's **Mail-flow probe** to send a
synthetic test message and capture the transaction. Interactively:
```
# Send a test through the customer's MX, capturing the full SMTP dialog
swaks --to postmaster@example.com --server mx.example.com --quit-after RCPT
```
Omit `--quit-after RCPT` to actually deliver the test.

## LDAP / Active Directory

### `ldapsearch`
Mirrors the portal's **Directory** query console.
```
ldapsearch -H ldap://dc01.corp.example.com -D 'svc-meridian@corp' \
           -w "$LDAP_PW" -b 'dc=corp,dc=example,dc=com' \
           '(sAMAccountName=jdoe)' cn mail title
```
LDAPS (TLS) is identical with `-H ldaps://...`; add `-ZZ` to require
`STARTTLS`.

## IP / subnet math

### `ipcalc`
Subnet arithmetic. Mirrors the portal's **IPAM subnet planner**.
```
ipcalc 192.168.50.0/24              # network, broadcast, host range
ipcalc -s 192.168.50.0/24 /26       # split /24 into /26s
```

## TLS / certificates

### `openssl s_client`
Interactive TLS probe; the **Certificates → Probe** page runs this under
the hood.
```
openssl s_client -connect meridiannip.meridian.local:443 -servername meridiannip.meridian.local </dev/null \
  | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256
```

### `openssl x509`
Inspect a cert on disk (expiry, SANs, key type).
```
openssl x509 -in /etc/letsencrypt/live/meridiannip.meridian.local/fullchain.pem \
             -noout -text | grep -E '(Subject:|DNS:|Not After|Signature Algorithm)'
```

### `certbot`
LE certificate lifecycle (issue, renew, revoke). Mirrors the portal's
**Certificates → Issue** flow.
```
certbot certificates                 # list managed certs
certbot renew --dry-run              # test the renewal path
```

## Network ops

### `ping` / `traceroute` / `mtr`
Hop-by-hop path + loss stats. Used by the portal's **Network Tools →
Path** widget.
```
mtr -rwc 20 1.1.1.1                  # 20 cycles, report mode
```

### `arping`
ARP-level reachability and MAC discovery on an L2 segment.
```
arping -I eth0 -c 3 192.168.50.1
```

### `nmap`
Host / port / service discovery. Meridian's **Vulnerability scan** and
**Subnet sweep** tools drive nmap with a curated script set.
```
nmap -sn 192.168.50.0/24             # live-host sweep
nmap -sV --script=banner 192.168.50.240 -p 443
```

### `tcpdump`
Packet capture. Meridian's **Packet-capture sandbox** runs this in a
confined AppArmor profile. CLI equivalent:
```
tcpdump -i eth0 -nn -c 100 'port 53'
```

### `snmpwalk` / `snmpget`
Classic SNMP. Mirrors the portal's **SNMP walk** tool.
```
snmpwalk -v2c -c public 192.168.50.1 system
```

## Format validators

### `jq`
JSON query / validate.
```
echo '{"a":1}' | jq .                # pretty-print + parse-check
curl -s http://127.0.0.1:8000/healthz | jq .
```

### `yq`
YAML counterpart of jq (wraps jq underneath).
```
yq . /etc/meridian/meridian.conf.yaml 2>/dev/null || echo 'not YAML'
```

### `xmllint`
XML validate / pretty-print. Useful for SAML IdP metadata blobs (the portal's
**SSO → Metadata** check).
```
xmllint --noout idp-metadata.xml && echo 'valid XML'
```

## System / process diagnosis

| Tool       | Purpose                                    |
|------------|--------------------------------------------|
| `htop`     | Interactive process + CPU/memory monitor   |
| `lsof`     | Open files + bound ports (`lsof -iTCP:443`)|
| `ss`       | Socket state (`ss -Htnlp sport = :443`)    |
| `ethtool`  | NIC link / ring / offload inspection       |
| `journalctl -u <svc>` | Service logs (`meridian-app`, `nginx`) |
| `systemctl status <svc>` | Service state + last 10 log lines |

## Meridian-specific

### `meridian-nip`
CLI shim installed by `install.sh` at `/usr/local/bin/meridian-nip`. Wraps
the internal `app.cli` so admins can run maintenance without activating the
venv manually.
```
meridian-nip doctor                  # same health checks as the portal's status page
meridian-nip users list --role admin
meridian-nip license install --key MRD-...
```

---

*File last updated by the installer; regenerated whenever `install.sh`'s
package list changes. To request a new entry, open a PR adding the tool to
both `install.sh`'s package list and this file.*
