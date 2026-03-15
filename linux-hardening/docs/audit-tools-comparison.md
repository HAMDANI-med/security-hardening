# Audit Tools Comparison — Lynis vs Debian CIS Benchmark

## Why Use Two Tools?

A common question when starting a hardening project is: *why run two audit tools?* The answer is that they measure different things and complement each other.

| Dimension | Lynis | Debian CIS |
|-----------|-------|-----------|
| **Output format** | Score (0–100) + categorized findings | Pass/Fail per check + conformity % |
| **Strictness** | Moderate | High (L1 baseline minimum) |
| **Coverage** | Broad (kernel, network, services, crypto, packages) | Deep (specific CIS control numbers) |
| **Best for** | Quick overall health check + discovering unknown issues | Compliance validation against a specific standard |
| **False positives** | Low | Low (binary pass/fail per control) |

---

## Lynis — Deep Dive

### Score Interpretation

The Hardening Index (0–100) is not a compliance score — it reflects the percentage of hardening recommendations that are satisfied:

| Range | Interpretation |
|-------|---------------|
| 0–50 | Poor — significant hardening gaps |
| 51–70 | Moderate — common baseline issues present |
| 71–85 | Good — most standard hardening applied |
| 86–100 | Excellent — comprehensive hardening |

An initial score of **64** means roughly a third of Lynis's recommendations were unmet — this aligns with a fresh Debian install which prioritizes stability over security.

### Key Finding Categories

**Warnings** (high-priority, should be addressed immediately):
- Missing security tools (auditd, fail2ban)
- SUID binaries in unexpected locations
- Bootloader without password protection
- Services running unnecessarily

**Suggestions** (medium-priority, optional but recommended):
- Kernel parameter tuning (sysctl)
- SSH cipher hardening
- File permission tightening

### Lynis Modules Used

```
- Security audit    [V]   — Active
- Vulnerability scan [V]   — Active
- Compliance status [?]   — Requires Lynis Enterprise for full output
```

### Running Lynis

```bash
# Download
git clone https://github.com/CISOfy/lynis

# Run as root for full coverage
sudo ./lynis audit system

# Key output files
# - /var/log/lynis.log        (full debug log)
# - /var/log/lynis-report.dat (structured findings)
```

---

## Debian CIS Benchmark — Deep Dive

### Score Interpretation

The Conformity Percentage is a direct ratio of passed controls:

```
Conformity % = (Passed Checks / Total Enabled Checks) × 100
```

Initial: **112/243 = 46.09%** — meaning 131 controls were actively failing.

### Control Structure

Controls are organized in 7 sections:

| Section | Focus Area | Controls (approx.) |
|---------|------------|-------------------|
| 1 | Initial configuration (partitions, modules) | ~40 |
| 2 | Services | ~30 |
| 3 | Network configuration | ~25 |
| 4 | Logging and auditing | ~30 |
| 5 | Access, authentication, authorization | ~70 |
| 6 | System configuration (permissions, etc.) | ~30 |
| 7 | Maintenance | ~18 |

The majority of failures in an initial Debian install cluster in **sections 4 (audit)**, **5 (authentication)**, and **1 (partitions)**.

### Audit vs Apply Mode

```bash
# AUDIT ONLY — read-only, safe to run any time
sudo ./bin/hardening.sh --audit --allow-unsupported-distribution

# APPLY — makes actual changes (use with caution)
sudo ./bin/hardening.sh --apply --allow-unsupported-distribution

# APPLY specific check only
sudo ./bin/hardening.sh --apply --only 4.1.1.1_install_auditd
```

> **Important:** Always run `--audit` first. Some `--apply` actions (like partition remounting or kernel module blacklisting) can cause service interruptions if applied incorrectly.

### Reading CIS Output

```
4.1.1.1_install_auditd  [ KO ] auditd is not installed!
4.1.1.1_install_auditd  [ KO ] Check Failed
```

Each check outputs:
- `[OK]` — control is satisfied
- `[KO]` — control is not satisfied (with explanation)
- `[INFO]` — informational context

---

## Combining Both Tools Effectively

### Workflow

```
1. Run Lynis     → Get overall picture, catch unknown issues
2. Run CIS       → Get specific control-level failures
3. Cross-reference → Prioritize issues flagged by BOTH tools
4. Apply fixes
5. Re-run BOTH   → Validate improvement in both metrics
```

### When Findings Conflict

Occasionally Lynis and CIS will disagree. For example:
- Lynis might suggest a sysctl value that CIS doesn't test
- CIS might require a strict file permission that Lynis would mark as acceptable

In these cases, **CIS takes precedence** for compliance purposes, but Lynis findings should not be dismissed — they often catch real-world risks that compliance frameworks haven't formalized yet.

---

## Limitations

### Lynis Limitations
- No specific remediation commands — it identifies issues but doesn't provide one-click fixes
- Score can be "gamed" by installing tools without using them properly (e.g., installing auditd without proper rules configured)
- Enterprise features (compliance mapping to HIPAA, PCI-DSS) require a paid license

### CIS Benchmark Limitations
- Some checks are environment-specific and will always fail in certain configurations (e.g., partition checks on single-partition installs)
- The `--apply` mode doesn't always handle edge cases gracefully — manual verification is recommended
- Upgrading Debian may reset some configurations, requiring re-audit

---

*Reference: Lynis 3.1.6 | debian-cis (CIS Debian Linux Benchmark)*
