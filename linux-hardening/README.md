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

Lynis is an open-source security auditing tool developed by CISOfy, designed specifically for Unix/Linux systems.

| Feature | Details |
|---------|---------|
| **Scope** | 400+ security checks across authentication, network, services, kernel, file integrity |
| **Output** | Hardening Index (0–100), categorized findings: Warnings, Suggestions |
| **Approach** | Read-only by default — non-intrusive |
| **Compliance** | PCI-DSS, HIPAA, ISO 27001 reference mappings |
| **Installation** | No permanent install required; portable single-directory execution |

```bash
./lynis audit system
```

### Debian CIS Benchmark (debian-cis)

Open-source implementation of CIS Benchmarks for Debian, maintained by the community.

| Feature | Details |
|---------|---------|
| **Origin** | Center for Internet Security — globally recognized hardening standards |
| **Structure** | 7 sections: Initial Config, Services, Network, Logging, Access/Auth, System Config, Maintenance |
| **Level 1** | Baseline recommendations, minimal functionality impact |
| **Level 2** | Advanced controls for high-security environments |
| **Modes** | `--audit` (check only) / `--apply` (auto-remediate) |

```bash
sudo ./bin/hardening.sh --audit --allow-unsupported-distribution
```

---

## Initial Audit Results

### Summary

| Tool | Metric | Score | Interpretation |
|------|--------|-------|----------------|
| **Debian CIS** | Conformity Percentage | **46.09%** | Less than half of CIS controls are met — default Debian configuration exposes significant risks |
| **Lynis** | Hardening Index | **64 / 100** | Important configuration weaknesses present; several baseline security tools missing |

**CIS Detail:** 112 / 243 checks passed | 131 / 243 failed

**Root cause:** High attack surface (unnecessary packages installed) combined with a weak defensive posture (unsecured partitions, missing audit/detection tooling).

### Screenshots

| Lynis Initial Scan | CIS Initial Summary |
|-------------------|---------------------|
| ![Lynis scan details](screenshots/lynis-initial.png) | ![CIS summary](screenshots/cis-initial-summary.png) |

---

## Problem Categories

### 1. Critical Partition Configuration (CIS Section 1.1)

**Problem:** `/tmp`, `/var`, and `/home` are not mounted with security options (`nodev`, `nosuid`, `noexec`).

**Consequence:** Non-privileged users can execute malicious binaries and scripts from these partitions, enabling local privilege escalation.

**Affected rules:** `1.1.3_tmp_nodev`, `1.1.4_tmp_nosuid`, `1.1.5_tmp_noexec`

![tmp_nodev audit](screenshots/cis-audit-tmp-nodev.png)

---

### 2. Unnecessary Services and Software (CIS Section 2.2)

**Problem:** The machine ships with software irrelevant for a server: X Window System, Avahi, CUPS.

**Consequence:** Each unnecessary package increases the attack surface — every CVE against these packages is a potential entry point.

**Affected rules:** `2.2.2_disable_xwindow_system`, `2.2.3_disable_avahi_server`, `2.2.4_disable_print_server`

![avahi audit](screenshots/cis-audit-avahi.png)

---

### 3. Missing Audit and Logging Infrastructure (CIS Section 4)

**Problem:** `auditd` is not installed. No file integrity monitoring (FIM) tool is configured.

**Consequence:** Zero traceability for critical events (account creation, file modification). Intrusion detection and forensic investigation are impossible.

![auditd audit](screenshots/cis-audit-auditd.png)

---

### 4. Incomplete SSH Hardening (CIS Section 5.2)

**Problem:** Root login is disabled, but cryptographic parameters, idle timeout, and connection limits are not configured.

**Consequence:** Vulnerability to brute-force attacks and exploitation of weak cipher suites.

**Affected rules:** `5.2.1_sshd_conf_perm_ownership`, `5.2.16_sshd_idle_timeout`

![SSH idle timeout audit](screenshots/cis-audit-ssh-timeout.png)

---

## 10 Priority Remediations

### Selection Rationale

Remediations were selected based on a **risk × implementation effort** matrix:

| # | Remediation | Risk Category | Effort | Priority |
|---|-------------|--------------|--------|---------|
| 1 | Install auditd | Forensics / Detection | Low | 🔴 Critical |
| 2 | /tmp nosuid | Privilege Escalation | Low | 🔴 Critical |
| 3 | SSH config permissions | Access Control | Low | 🔴 Critical |
| 4 | Disable X Window | Attack Surface | Low | 🟠 High |
| 5 | Disable IPv6 | Network Hygiene | Low | 🟠 High |
| 6 | Password complexity (pwquality) | Authentication | Medium | 🟠 High |
| 7 | GRUB password | Physical Access | Medium | 🔴 Critical |
| 8 | Install fail2ban | Brute-force Defense | Low | 🟠 High |
| 9 | Restrict core dumps | Data Confidentiality | Low | 🟡 Medium |
| 10 | Default umask 077 | Permission Hygiene | Low | 🟡 Medium |

---

## Remediations Applied

### 1. Install and Enable `auditd`

**Risk:** Without auditd, the server is "blind" — no forensic trail exists after an intrusion.

**Initial state:**
```
4.1.1.1_install_auditd  [ KO ] auditd is not installed!
```

**Remediation:**
```bash
sudo apt install auditd -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

**Result:**
```
auditd.service - Security Auditing Service
  Active: active (running)
```

| Before | After |
|--------|-------|
| ![auditd before](screenshots/auditd-before.png) | ![auditd after](screenshots/auditd-after.png) |

---

### 2. Restrict SUID Bit on `/tmp` (nosuid)

**Risk:** SUID binaries in `/tmp` can be used to elevate privileges to root without any exploit.

**Initial state:**
```
/dev/mapper/debian12--vg-tmp /tmp  ext4  defaults  0  2
```

**Remediation:**
```bash
sudo sed -i '/\/tmp\s/s/defaults/defaults,nosuid/' /etc/fstab
sudo mount -o remount /tmp
```

**Verification:**
```bash
grep " /tmp " /proc/mounts
# /dev/mapper/debian12--vg-tmp /tmp ext4 rw,nosuid,relatime 0 0
```

| Before | After |
|--------|-------|
| ![nosuid before](screenshots/nosuid-before.png) | ![nosuid after](screenshots/nosuid-after.png) |

---

### 3. Fix SSH Config File Permissions

**Risk:** World-readable `sshd_config` allows unprivileged users to see (or modify, if writable) the SSH configuration, potentially inserting backdoors.

**Initial state:**
```
-rw-r--r-- 1 root root 3242 /etc/ssh/sshd_config
```

**Remediation:**
```bash
sudo chmod 600 /etc/ssh/sshd_config
```

**Result:**
```
-rw------- 1 root root 3242 /etc/ssh/sshd_config
```

| Before | After |
|--------|-------|
| ![SSH perms before](screenshots/ssh-perms-before.png) | ![SSH perms after](screenshots/ssh-perms-after.png) |

---

### 4. Remove X Window System

**Risk:** `xserver-xorg-core`, `xserver-common`, `xserver-xephyr` are server-grade X11 packages. Each carries CVEs. None are needed on a headless server.

**Initial state:**
```
xserver-common    2:21.1.7-3+deb12u11
xserver-xephyr    2:21.1.7-3+deb12u11
xserver-xorg-core 2:21.1.7-3+deb12u11
```

**Remediation:**
```bash
sudo apt purge xserver-xorg-core xserver-common xserver-xephyr avahi-daemon cups -y
```

**Result:** All X11 packages removed. Attack surface reduced significantly.

| Before | After |
|--------|-------|
| ![xwindow before](screenshots/xwindow-before.png) | ![xwindow after](screenshots/xwindow-after.png) |

---

### 5. Disable IPv6

**Risk:** If IPv6 is not actively monitored, traffic can bypass IPv4 firewall rules — creating an unmonitored communication channel.

**Initial state:**
```bash
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
# 0
```

**Remediation:**
```bash
sudo tee -a /etc/sysctl.conf << EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sudo sysctl -p
```

**Verification:**
```bash
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
# 1
```

| Before | After |
|--------|-------|
| ![ipv6 before](screenshots/ipv6-before.png) | ![ipv6 after](screenshots/ipv6-after.png) |

---

### 6. Enforce Password Complexity via `pwquality`

**Risk:** Without password complexity rules, users create trivially weak passwords vulnerable to dictionary attacks.

**Initial state (pwquality.conf):**
```ini
# minlen = 8
# dcredit = 0
# ucredit = 0
# lcredit = 0
# ocredit = 0
minlen = 12
```

**Remediation** (`/etc/security/pwquality.conf`):
```ini
# Minimum 14 characters
minlen = 14

# At least 1 digit
dcredit = -1

# At least 1 uppercase
ucredit = -1

# At least 1 special character
ocredit = -1

# At least 1 lowercase
lcredit = -1
```

| Before | After |
|--------|-------|
| ![pwquality before](screenshots/pwquality-before.png) | ![pwquality after](screenshots/pwquality-after.png) |

---

### 7. Protect GRUB Bootloader

**Risk:** Physical access to the server allows boot parameter modification (e.g., `init=/bin/bash`) to obtain a root shell without any password — bypassing all software security.

**Remediation:**

```bash
# Generate a PBKDF2 hashed password
sudo grub-mkpasswd-pbkdf2
```

Add to `/etc/grub.d/40_custom`:
```bash
set superusers="grubadmin"
password_pbkdf2 grubadmin grub.pbkdf2.sha512.10000.<hash>
```

```bash
sudo update-grub
```

**Result:** GRUB menu editing now requires the `grubadmin` password.

| Before | After |
|--------|-------|
| ![GRUB before](screenshots/grub-before.png) | ![GRUB after](screenshots/grub-after.png) |

---

### 8. Install and Enable `fail2ban`

**Risk:** SSH and other exposed services are constantly scanned. Without rate-limiting, brute-force attacks run unchecked.

**Remediation:**
```bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

**Verification:**
```bash
sudo fail2ban-client status sshd
# Status for the jail: sshd
# |- Filter: Currently failed: 0 | Total failed: 0
# `- Actions: Currently banned: 0 | Total banned: 0
```

| Before | After |
|--------|-------|
| ![fail2ban before](screenshots/fail2ban-before.png) | ![fail2ban after](screenshots/fail2ban-after.png) |

---

### 9. Restrict Core Dumps

**Risk:** Core dump files can contain sensitive in-memory data: private keys, passwords, session tokens. If a privileged service crashes, this data is written to disk in plaintext.

**Remediation** (`/etc/security/limits.conf`):
```
# Restrict Core Dumps (hard limit)
* hard core 0
```

**Verification:**
```bash
grep -E '^\s*\*.*\shw\ward\s+core\s+0' /etc/security/limits.conf
# * hard core 0
```

| Before | After |
|--------|-------|
| ![coredump before](screenshots/coredump-before.png) | ![coredump after](screenshots/coredump-after.png) |

---

### 10. Set Default `umask` to 077

**Risk:** The default `umask 022` creates files readable by any user on the system. This leaks data between users unintentionally.

**Remediation** (`/etc/bash.bashrc` and `/etc/profile`):
```bash
sudo tee -a /etc/bash.bashrc << EOF
# CIS 5.4.4: Set default umask for users
umask 077
EOF
```

**Effect:** Files created by users are now `rw-------` (600) and directories are `rwx------` (700) by default.

| Before | After |
|--------|-------|
| ![umask before](screenshots/umask-before.png) | ![umask after](screenshots/umask-after.png) |

---

## Post-Remediation Audit

### Results Summary

| Metric | Initial | Post-Remediation | Change |
|--------|---------|-----------------|--------|
| **CIS Conformity %** | 46.09% | **51.02%** | **+4.93 points** |
| **CIS Passed Checks** | 112 / 243 | **124 / 243** | **+12 checks** |
| **Lynis Hardening Index** | 64 / 100 | **68 / 100** | **+4 points** |

### Screenshots

| CIS Post-Audit | Lynis Post-Audit |
|---------------|-----------------|
| ![CIS post](screenshots/cis-post-remediation.png) | ![Lynis post](screenshots/lynis-post-remediation.png) |

### Per-Remediation Confirmation

| # | Check | Post-Remediation Status |
|---|-------|------------------------|
| 1 | `4.1.1.1_install_auditd` | ✅ `auditd is installed` |
| 2 | `1.1.4_tmp_nosuid` | ✅ `/tmp has nosuid in fstab` + `/tmp mounted with nosuid` |
| 3 | `5.2.1_sshd_conf_perm_ownership` | ✅ `correct ownership` + `correct permissions` |
| 4 | `2.2.2_disable_xwindow_system` | ✅ All X11 packages absent |
| 5 | `3.1.1_disable_ipv6` | ✅ `ipv6 is disabled` |
| 6 | `5.3.1_enable_pwquality` | ✅ All complexity parameters set |
| 7 | `BOOT-5122` (Lynis) | ✅ GRUB password protection enabled |
| 8 | `DEB-0880` (Lynis) | ✅ `fail2ban installed with jail.local` |
| 9 | `1.6.4_restrict_core_dumps` | ✅ `hard core 0` in limits.conf |
| 10 | `5.4.4_default_umask` | ✅ `umask 077` in bash.bashrc and profile |

---

## Remaining Issues

Despite the 10 remediations, 119 CIS checks still fail. The main categories are:

### File Integrity Monitoring (Priority: Immediate)
`1.4.1_install_tripwire` and Lynis `FINT-4350` — No FIM tool installed. The server is vulnerable to stealthy file modifications by attackers who gain access.

**Remediation:** Install AIDE or Tripwire with an initial baseline database.

### Kernel/Network Hardening (Priority: High)
Sections 3.2 and 3.3 — sysctl parameters for route validation and suspicious packet logging remain unconfigured:
```bash
net.ipv4.conf.all.rp_filter = 1      # Anti-spoofing
net.ipv4.conf.all.log_martians = 1   # Log suspicious packets
```

### PAM Account Lockout (Priority: High)
`5.3.2_enable_lockout_failed_password` — `pam_faillock` is not configured. fail2ban protects at the network level, but PAM-level lockout provides an additional defense layer.

### Permissions Cleanup (Priority: Medium)
- Unowned files and directories detected by CIS Section 6.1
- Overly permissive log file permissions (`4.2.3_logs_permissions`)
- World-writable files and SUID/SGID cleanup pending

---

## Security Roadmap

### Current State

```
Conformity: 51.02%  ████████████░░░░░░░░░░░░  Target: 85-90%
```

### Immediate Actions (Next 30 Days)

| Action | Command / Tool | Impact |
|--------|---------------|--------|
| Install AIDE (FIM) | `apt install aide && aideinit` | Detects unauthorized file changes |
| Configure pam_faillock | Edit `/etc/pam.d/common-auth` | PAM-level account lockout |
| Apply sysctl hardening | Add to `/etc/sysctl.conf` | Anti-spoofing, log suspicious traffic |
| Clean SUID/SGID | `find / -perm /6000 -type f` | Remove unnecessary elevated binaries |

### Medium-Term Improvements

| Axis | Action | Justification |
|------|--------|--------------|
| **Mandatory Access Control** | Configure AppArmor profiles for SSH and web services | Contain damage if a service is compromised |
| **Centralized Logging** | Forward logs to a remote SIEM | Protect evidence against log-wiping by attackers |
| **SSH Key-Only Auth** | Disable password authentication, require public key | Eliminates brute-force attack surface entirely |
| **Configuration Management** | Deploy Ansible playbooks for CIS controls | Prevent configuration drift after updates |

### Audit Schedule

| Type | Frequency | Tool | Scope |
|------|-----------|------|-------|
| **Light audit** | Monthly | Lynis / targeted CIS | Critical checks, service status |
| **Full audit** | Quarterly | Full CIS + Lynis | All 243 controls |
| **FIM verification** | Daily (automated via cron) | AIDE / Tripwire | All monitored files |

### Patch Management

```bash
# Enable unattended security updates
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

---

## File Structure

```
linux-hardening/
├── README.md                       # This document
├── docs/
│   ├── audit-tools-comparison.md  # Lynis vs CIS Benchmark analysis
│   └── sysctl-hardening.md        # Kernel hardening reference
└── screenshots/                    # All audit and remediation screenshots
```

---

*Author: HAMDANI Mohammed | Platform: Debian 12 (Bookworm) | Frameworks: CIS Benchmark (debian-cis) + Lynis 3.1.6*
