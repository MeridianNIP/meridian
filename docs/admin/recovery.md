# Admin recovery — breaking out of a lockout

When the portal is reachable but SSH isn't, or SSH is open but nobody has
a working key, you're locked out. This page describes every recovery path
in order from least-invasive to most-invasive. All of them require
**console or local shell** access to the host running Meridian — the idea
is that physical or VM-console access is your last-resort credential, not
a password-reset email.

---

## Decision tree

1. **Can you reach the portal UI?** (HTTPS on 443 still works even if SSH
   is blocked.) → go to **[A. Portal still works](#a-portal-still-works)**.
2. **Can you get a VM / hypervisor console on the host?** → **[B. Console login](#b-console-login)**.
3. **Can you boot into a rescue shell or single-user mode?** → **[C. Rescue shell](#c-rescue-shell)**.

---

## A. Portal still works

If your browser can still load the portal, you don't need SSH to recover.

### Unban yourself via the Fail2ban admin card

1. Log in as a `super_admin`.
2. Go to **Admin Panel → System Health**.
3. Scroll to the **Fail2ban jails** card.
4. Find your IP in the per-jail **Banned IPs** list and click **Unban**
   — or click **Unban + whitelist** to permanently add the IP to that
   jail's in-memory ignore list.
5. For a permanent fix across reboots, edit `/etc/fail2ban/jail.local`
   on the host (see section B below) and add your admin CIDR to the
   `[DEFAULT] ignoreip = …` line.

That card is **super_admin only** by design — whitelisting touches the
security perimeter and shouldn't be available to the broader admin role.

---

## B. Console login

You have a VM console / physical keyboard on the host. SSH might be
banned, blocked, or just broken. Root has a password — it was set during
install and written to `/root/meridian-install.log`.

### Find your own IP first

You need to know which IP is being banned. Common cases:

| Where you are              | How to find your IP                          |
|----------------------------|----------------------------------------------|
| A Linux/macOS terminal     | `ip -4 addr show` (Linux) / `ifconfig` (macOS) |
| WSL on Windows             | `ip -4 addr show eth0` — **this is the IP fail2ban sees**, not your Windows IP |
| Docker Desktop (Windows)   | `docker run --rm busybox ip addr` — container IP. Docker NATs through the host, so fail2ban likely sees the **host's** IP |
| Plain Windows              | `ipconfig` in PowerShell |

### Log in as root on the console

Username `root`, password set at install. If you don't remember it, it's
in `/root/meridian-install.log` on the host.

### Check if you're actually banned

```
fail2ban-client status
fail2ban-client status sshd
```

The **Banned IP list** at the bottom of the `sshd` section is what you
care about. If your IP is there, you're banned.

### Unban one IP, now

```
fail2ban-client set sshd unbanip 192.168.50.196     # replace with your IP
```

Replace `sshd` with whichever jail banned you (`nginx-req-limit`,
`meridian-login`, etc.) — the earlier `status` command listed every jail.

### Prevent future bans from your subnet

```
fail2ban-client set sshd addignoreip 192.168.50.0/24
```

This lasts until fail2ban is restarted. For **permanent** whitelisting,
edit `/etc/fail2ban/jail.local`:

```
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 192.168.50.0/24
```

…then reload:

```
fail2ban-client reload
```

### Nuclear option — stop fail2ban entirely

If you're in the middle of an outage and you'll turn it back on after
you're back in:

```
systemctl stop fail2ban       # stops banning
# (do what you need)
systemctl start fail2ban      # re-enable
```

Leave it off only as long as you must — `fail2ban-client` over SSH (from
a re-granted session) is almost always faster.

### Re-key SSH so you don't need console again

While you're root on the console, install an SSH pubkey so the next
recovery doesn't need the console:

```
mkdir -p /root/.ssh
echo 'ssh-ed25519 AAAA… your-admin@workstation' >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
```

Or, for the deploy-friendly account:

```
install -d -m 700 -o meridian-user -g meridian-user /home/meridian-user/.ssh
echo 'ssh-ed25519 AAAA… your-admin@workstation' >> /home/meridian-user/.ssh/authorized_keys
chown meridian-user:meridian-user /home/meridian-user/.ssh/authorized_keys
chmod 600 /home/meridian-user/.ssh/authorized_keys
```

---

## C. Rescue shell

SSH is gone **and** you can't log in on the console (password forgotten,
account corrupted). Then you need the bootloader.

### Debian GRUB rescue

1. Reboot the VM. At the GRUB menu, press `e` on the default entry.
2. Find the `linux /boot/vmlinuz…` line and append `init=/bin/bash` to
   the end.
3. Press `Ctrl-X` (or F10) to boot with that override — you land on a
   root shell with `/` mounted read-only.
4. Remount writable: `mount -o remount,rw /`.
5. `passwd root` to reset the root password.
6. Fix anything else (e.g., re-install `/root/.ssh/authorized_keys`).
7. `sync; reboot -f` to come back up normally.

If the disk is encrypted (LUKS), you'll be prompted for the LUKS
passphrase before GRUB runs — that's an encryption layer, not a Meridian
layer.

---

## What Meridian does to prevent this

1. **`install.sh` prompts for an Admin CIDR** at setup and seeds
   `/etc/fail2ban/jail.local` with that CIDR in `ignoreip`. Your
   workstation subnet is whitelisted from day 1.
2. **`install.sh` prompts for an SSH pubkey** and installs it into
   `/root/.ssh/authorized_keys` AND `/home/meridian-user/.ssh/authorized_keys`
   so key-based SSH works at first boot without any `ssh-copy-id`.
3. **The Fail2ban admin card** (super_admin only) gives you portal-side
   unban capability as long as the portal is up. The portal listens on
   443; fail2ban bans only affect port 22 and the login filter.
4. **Sudoers drop-in** at `/etc/sudoers.d/meridian-fail2ban` lets the
   portal invoke `fail2ban-client` through a narrow command allow-list —
   view, unban, add/remove ignore. No reload, no jail start/stop, no
   config edits through the web.

If you're building a golden VM image, **answer both prompts** during
install. The Admin CIDR defaults to the detected LAN's /24, and the
pubkey field can take the output of `cat ~/.ssh/id_ed25519.pub`.
