# Screenshots

This folder contains all screenshots documenting the hardening process.

## Expected Files

### Initial Audit
- `lynis-initial.png` — Lynis scan details: Hardening Index 64, 260 tests
- `cis-initial-summary.png` — CIS SUMMARY: 112/243 passed, 46.09% conformity

### CIS Audit Screenshots (Initial)
- `cis-audit-tmp-nodev.png` — 1.1.3_tmp_nodev: KO
- `cis-audit-avahi.png` — 2.2.3_disable_avahi_server: KO (avahi-daemon installed)
- `cis-audit-auditd.png` — 4.1.1.1_install_auditd: KO
- `cis-audit-ssh-timeout.png` — 5.2.16_sshd_idle_timeout: KO

### Remediation 1 — auditd
- `auditd-before.png` — 4.1.1.1_install_auditd KO
- `auditd-after.png` — auditd.service active (running)

### Remediation 2 — /tmp nosuid
- `nosuid-before.png` — fstab entry: defaults (no nosuid)
- `nosuid-after.png` — fstab + /proc/mounts showing nosuid

### Remediation 3 — SSH permissions
- `ssh-perms-before.png` — -rw-r--r-- (644)
- `ssh-perms-after.png` — -rw------- (600)

### Remediation 4 — X Window removal
- `xwindow-before.png` — dpkg listing xserver-xorg-core installed
- `xwindow-after.png` — Empty dpkg listing (all removed)

### Remediation 5 — IPv6
- `ipv6-before.png` — /proc/sys/.../disable_ipv6 = 0
- `ipv6-after.png` — /proc/sys/.../disable_ipv6 = 1

### Remediation 6 — pwquality
- `pwquality-before.png` — pwquality.conf default values
- `pwquality-after.png` — minlen=14, dcredit=-1, ucredit=-1, etc.

### Remediation 7 — GRUB
- `grub-before.png` — Lynis BOOT-5122: password protection NONE
- `grub-after.png` — Lynis BOOT-5122: password protection OK

### Remediation 8 — fail2ban
- `fail2ban-before.png` — Lynis: fail2ban Not Installed
- `fail2ban-after.png` — fail2ban-client status sshd showing active jail

### Remediation 9 — Core dumps
- `coredump-before.png` — limits.conf: no core restriction
- `coredump-after.png` — limits.conf: * hard core 0

### Remediation 10 — umask
- `umask-before.png` — grep umask returns nothing in bash.bashrc
- `umask-after.png` — grep showing umask 077

### Post-Remediation Audit
- `cis-post-remediation.png` — CIS SUMMARY: 124/243 passed, 51.02%
- `lynis-post-remediation.png` — Lynis Hardening Index: 68

### Post-Remediation Per-Check Confirmations
- `post-auditd.png` — 4.1.1.1: OK auditd is installed
- `post-nosuid.png` — 1.1.4: OK /tmp mounted with nosuid
- `post-ssh-perms.png` — 5.2.1: OK correct permissions
- `post-xwindow.png` — 2.2.2: OK all absent
- `post-ipv6.png` — 3.1.1: OK ipv6 is disabled
- `post-pwquality.png` — 5.3.1: OK all parameters present
- `post-grub.png` — BOOT-5122: password protection OK
- `post-fail2ban.png` — DEB-0880: Installed with jail.local
- `post-coredumps.png` — 1.6.4: OK hard core 0 present
- `post-umask.png` — 5.4.4: OK umask 077 present
