# Linux Server Hardening — Defensive Posture Reinforcement

> Systematic hardening of a Debian 12 server using CIS Benchmark (debian-cis) and Lynis, with documented before/after states for 10 prioritized remediations.

---

## Table of Contents

1. [Audit Tools](#audit-tools)
2. [Initial Audit Results](#initial-audit-results)
3. [Problem Categories](#problem-categories)
4. [10 Priority Remediations](#10-priority-remediations)
5. [Remediations Applied](#remediations-applied)
6. [Post-Remediation Audit](#post-remediation-audit)
7. [Remaining Issues](#remaining-issues)
8. [Security Roadmap](#security-roadmap)

---

## Audit Tools

### Lynis

Open-source security auditing tool by CISOfy — 400+ checks, Hardening Index 0–100.

```bash
./lynis audit system
```

![Lynis running](screenshots/01-lynis-running.png)

### Debian CIS Benchmark

Open-source implementation of CIS controls for Debian. Audit mode only reads, apply mode remediates.

```bash
sudo ./bin/hardening.sh --audit --allow-unsupported-distribution
```

![CIS Benchmark running](screenshots/02-cis-benchmark-running.png)

---

## Initial Audit Results

| Tool | Metric | Score |
|------|--------|-------|
| **Debian CIS** | Conformity Percentage | **46.09%** |
| **Lynis** | Hardening Index | **64 / 100** |

CIS detail: **112 / 243 checks passed** — 131 failing.

**Lynis initial scan:**
![Lynis initial — Hardening Index 64](screenshots/03-lynis-initial-scan-details-score64.png)

**CIS initial summary:**
![CIS initial — 112/243, 46.09%](screenshots/04-cis-initial-summary-46percent.png)

---

## Problem Categories

### 1. Critical Partition Configuration (CIS Section 1.1)

`/tmp` is not mounted with `nosuid` — binaries in `/tmp` can elevate privileges.

![CIS audit — tmp nodev KO](screenshots/05-cis-audit-tmp-nodev-KO.png)

### 2. Unnecessary Services (CIS Section 2.2)

X Window System, Avahi, CUPS installed on a headless server — unnecessary attack surface.

![CIS audit — avahi-server KO](screenshots/06-cis-audit-avahi-server-KO.png)

### 3. Missing Audit Infrastructure (CIS Section 4)

`auditd` is not installed — no traceability, forensic investigation impossible.

![CIS audit — auditd KO](screenshots/07-cis-audit-auditd-KO.png)

### 4. Incomplete SSH Hardening (CIS Section 5.2)

Cryptographic parameters and idle timeout not configured — vulnerable to brute-force and weak ciphers.

![CIS audit — SSH idle timeout KO](screenshots/08-cis-audit-ssh-idle-timeout-KO.png)

---

## 10 Priority Remediations

| # | Remediation | Risk | Priority |
|---|-------------|------|---------|
| 1 | Install auditd | No forensics without it | 🔴 Critical |
| 2 | /tmp nosuid | Local privilege escalation | 🔴 Critical |
| 3 | SSH config permissions | SSH backdoor risk | 🔴 Critical |
| 4 | Disable X Window | Unnecessary attack surface | 🟠 High |
| 5 | Disable IPv6 | Firewall bypass risk | 🟠 High |
| 6 | Password complexity (pwquality) | Weak credential exploitation | 🟠 High |
| 7 | GRUB password | Physical access bypass | 🔴 Critical |
| 8 | Install fail2ban | Brute-force defense | 🟠 High |
| 9 | Restrict core dumps | Sensitive data in crash files | 🟡 Medium |
| 10 | Default umask 077 | Files readable by other users | 🟡 Medium |

---

## Remediations Applied

### 1. Install and Enable `auditd`

![auditd — initial state KO](screenshots/18-rem1-auditd-state-before.png)

```bash
sudo apt install auditd -y
```

![auditd — apt install](screenshots/19-rem1-auditd-apt-install.png)

```bash
sudo systemctl enable auditd
```

![auditd — systemctl enable](screenshots/20-rem1-auditd-systemctl-enable.png)

**Result — service active:**
![auditd — service running](screenshots/21-rem1-auditd-service-running.png)

---

### 2. Restrict SUID Bit on `/tmp` (nosuid)

**Initial state — fstab without nosuid:**
![nosuid — fstab before](screenshots/22-rem2-nosuid-fstab-before.png)

```bash
sudo sed -i '/\/tmp\s/s/defaults/defaults,nosuid/' /etc/fstab
sudo mount -o remount /tmp
```

![nosuid — sed command](screenshots/23-rem2-nosuid-fstab-sed-edit.png)

**Result — nosuid in fstab and active mount:**
![nosuid — fstab after + mount verify](screenshots/24-rem2-nosuid-fstab-after-mount.png)

---

### 3. Fix SSH Config File Permissions

**Initial state — permissions 644 (world-readable):**
![SSH perms — before (644)](screenshots/25-rem3-ssh-perms-before-644.png)

```bash
sudo chmod 600 /etc/ssh/sshd_config
```

![SSH perms — chmod 600](screenshots/26-rem3-ssh-chmod-600.png)

**Result — permissions 600:**
![SSH perms — after (600)](screenshots/27-rem3-ssh-perms-after-600.png)

---

### 4. Remove X Window System

**Initial state — X11 packages installed:**
![X Window — packages before](screenshots/28-rem4-xwindow-packages-before.png)

```bash
sudo apt purge xserver-xorg-core xserver-common xserver-xephyr avahi-daemon cups -y
```

![X Window — apt purge](screenshots/29-rem4-xwindow-apt-purge.png)

**Result — all packages removed:**
![X Window — packages after (empty)](screenshots/30-rem4-xwindow-packages-after.png)

---

### 5. Disable IPv6

**Initial state — IPv6 enabled (value 0):**
![IPv6 — before (value 0)](screenshots/31-rem5-ipv6-before-value0.png)

```bash
sudo tee -a /etc/sysctl.conf << EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sudo sysctl -p
```

![IPv6 — sysctl.conf edited](screenshots/32-rem5-ipv6-sysctl-conf.png)

**Result — IPv6 disabled (value 1):**
![IPv6 — after (value 1)](screenshots/33-rem5-ipv6-after-value1.png)

---

### 6. Enforce Password Complexity via `pwquality`

**Initial state — minimal configuration:**
![pwquality — before](screenshots/34-rem6-pwquality-before.png)

```bash
sudo nano /etc/security/pwquality.conf
```

![pwquality — nano opened](screenshots/35-rem6-pwquality-nano-access.png)

Configuration applied — minlen=14, dcredit=-1, ucredit=-1, ocredit=-1, lcredit=-1:

![pwquality — config edited](screenshots/36-rem6-pwquality-conf-edited.png)

**Result — all parameters verified:**
![pwquality — after verify](screenshots/37-rem6-pwquality-after-verify.png)

---

### 7. Protect GRUB Bootloader

```bash
sudo grub-mkpasswd-pbkdf2
```

![GRUB — mkpasswd hash generated](screenshots/38-rem7-grub-mkpasswd-hash.png)

```bash
sudo tee -a /etc/grub.d/40_custom << EOF
set superusers="grubadmin"
password_pbkdf2 grubadmin <hash>
EOF
```

![GRUB — 40_custom configured](screenshots/39-rem7-grub-40custom-config.png)

```bash
sudo update-grub
```

**Result — GRUB password protection active:**
![GRUB — update-grub output](screenshots/40-rem7-grub-update-grub-output.png)

---

### 8. Install and Enable `fail2ban`

```bash
sudo apt install fail2ban -y
```

![fail2ban — apt install](screenshots/41-rem8-fail2ban-apt-install.png)

```bash
sudo systemctl enable fail2ban
```

![fail2ban — systemctl enable + active](screenshots/42-rem8-fail2ban-systemctl-enable.png)

**Result — jail active for SSH:**
![fail2ban — status sshd](screenshots/43-rem8-fail2ban-status-sshd.png)

---

### 9. Restrict Core Dumps

**Initial state — no restriction in limits.conf:**
![Core dumps — before](screenshots/44-rem9-coredumps-before.png)

```bash
sudo tee -a /etc/security/limits.conf << EOF
* hard core 0
EOF
```

![Core dumps — limits.conf edited](screenshots/45-rem9-coredumps-limits-conf.png)

**Result:**
![Core dumps — after verify](screenshots/46-rem9-coredumps-after-verify.png)

---

### 10. Set Default `umask` to 077

**Initial state — no umask in bash.bashrc:**
![umask — before](screenshots/47-rem10-umask-before.png)

```bash
sudo tee -a /etc/bash.bashrc << EOF
umask 077
EOF
```

![umask — bashrc edited](screenshots/48-rem10-umask-bashrc-edit.png)

**Result — umask 077 active:**
![umask — after verify](screenshots/49-rem10-umask-after-verify.png)

---

## Post-Remediation Audit

| Metric | Initial | Post-Remediation | Change |
|--------|---------|-----------------|--------|
| **CIS Conformity %** | 46.09% | **51.02%** | **+4.93 pts** |
| **CIS Passed Checks** | 112 / 243 | **124 / 243** | **+12 checks** |
| **Lynis Hardening Index** | 64 / 100 | **68 / 100** | **+4 pts** |

**CIS post-remediation — 51.02%:**
![CIS post — 124/243, 51.02%](screenshots/50-post-cis-summary-51percent.png)

**Lynis post-remediation — score 68:**
![Lynis post — Hardening Index 68](screenshots/51-post-lynis-score68.png)

### Per-Check Confirmation

**1. auditd installed:**
![Post — auditd OK](screenshots/52-post-auditd-OK.png)

**2. /tmp nosuid:**
![Post — nosuid OK](screenshots/53-post-nosuid-OK.png)

**3. SSH permissions:**
![Post — SSH perms OK](screenshots/54-post-ssh-perms-OK.png)

**4. X Window removed:**
![Post — X Window OK](screenshots/55-post-xwindow-OK.png)

**5. IPv6 disabled:**
![Post — IPv6 OK](screenshots/56-post-ipv6-OK.png)

**6. pwquality configured:**
![Post — pwquality OK](screenshots/57-post-pwquality-OK.png)

**7. GRUB protected:**
![Post — GRUB OK](screenshots/58-post-grub-OK.png)

**8. fail2ban active:**
![Post — fail2ban OK](screenshots/59-post-fail2ban-OK.png)

**9. Core dumps restricted:**
![Post — core dumps OK](screenshots/60-post-coredumps-OK.png)

**10. umask 077:**
![Post — umask OK](screenshots/61-post-umask-OK.png)

---

## Remaining Issues

| Category | Details |
|----------|---------|
| **File Integrity (FIM)** | `tripwire` / AIDE not installed — no detection of stealthy file modifications |
| **Kernel/Network** | sysctl sections 3.2–3.3 not applied (rp_filter, log_martians) |
| **PAM lockout** | `pam_faillock` not configured — fail2ban protects at network level only |
| **Permissions cleanup** | Unowned files, world-writable files, SUID/SGID review pending |

---

## Security Roadmap

```
Current:  51.02%  ████████████░░░░░░░░░░░░  Target: 85-90%
```

### Immediate (Next 30 Days)

| Action | Tool | Impact |
|--------|------|--------|
| Install AIDE (FIM) | `apt install aide && aideinit` | Detects unauthorized file changes |
| Configure pam_faillock | Edit `/etc/pam.d/common-auth` | PAM-level account lockout |
| Apply sysctl hardening | Add to `/etc/sysctl.d/99-hardening.conf` | Anti-spoofing, suspicious traffic logging |
| Clean SUID/SGID | `find / -perm /6000 -type f` | Remove unnecessary elevated binaries |

### Medium Term

| Axis | Action |
|------|--------|
| Access control | Configure AppArmor profiles for SSH |
| Centralized logging | Forward logs to SIEM |
| SSH hardening | Disable password auth, require public key only |
| Automation | Deploy Ansible playbooks for CIS controls |

### Audit Schedule

| Type | Frequency | Scope |
|------|-----------|-------|
| Light audit | Monthly | Critical checks, service status |
| Full audit | Quarterly | All 243 CIS controls |
| FIM verification | Daily (cron) | All monitored files |

---

*Author: HAMDANI Mohammed | Platform: Debian 12 (Bookworm) | Frameworks: CIS Benchmark (debian-cis) + Lynis 3.1.6*
