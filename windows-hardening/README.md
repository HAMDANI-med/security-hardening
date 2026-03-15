# Windows 11 Hardening — Defensive Posture Reinforcement

> Systematic hardening of a Windows 11 workstation using CIS Benchmark v2.0.0 and Microsoft Security Compliance Toolkit (MSCT).

---

## Table of Contents

1. [Frameworks Overview](#frameworks-overview)
2. [Initial Audit](#initial-audit)
3. [Gap Analysis](#gap-analysis)
4. [Critical Findings](#critical-findings)
5. [Hardening Applied](#hardening-applied)
6. [Post-Hardening Validation](#post-hardening-validation)
7. [Manual Security Tests](#manual-security-tests)
8. [Security Maturity Assessment](#security-maturity-assessment)
9. [Recommendations](#recommendations)
10. [6-Month Maintenance Plan](#6-month-maintenance-plan)

---

## Frameworks Overview

Two complementary frameworks were used and compared throughout this project.

### CIS Microsoft Windows 11 Stand-alone Benchmark v2.0.0

| Attribute | Details |
|-----------|---------|
| **Origin** | Center for Internet Security — independent non-profit, community-consensus model |
| **Philosophy** | Prescriptive and strict; maximizes security posture |
| **Level 1** | Low impact, applicable to any workstation without breaking functionality |
| **Level 2** | High security, may require extensive testing before deployment |
| **Use case** | Industry-standard compliance validation |

### Microsoft Security Compliance Toolkit (MSCT) — Windows 11 v25H2

| Attribute | Details |
|-----------|---------|
| **Origin** | Microsoft — developed and validated internally by the security team |
| **Philosophy** | Pragmatic; balances security with product compatibility |
| **Format** | Pre-configured Group Policy Objects (GPOs) |
| **Use case** | Managed enterprise environments, Active Directory integration |

### Key Differences

| Dimension | CIS Benchmark | Microsoft Baseline |
|-----------|--------------|-------------------|
| Authority | Independent community experts | OS vendor |
| Strictness | Higher (especially Level 2) | Moderate |
| Compatibility focus | Low | High |
| Deployment method | Manual or scripted | GPO / MSCT tool |
| Scope | Standalone + domain | Primarily domain-joined |

### 5 Common Rules (Cross-Reference)

| Rule | CIS Reference | Microsoft Baseline | Objective |
|------|-------------|-------------------|-----------|
| Rename admin account | 2.3.1.4 (L1) | Accounts: Rename administrator account | Prevent targeted brute-force on known account names |
| Max password age | 1.1.2 (L1) | Maximum password age | Force regular credential rotation |
| Account lockout threshold | 1.2.2 (L1) | Account lockout threshold | Block dictionary and brute-force attacks |
| LAN Manager auth level | 2.3.11.7 (L1) | Network security: LAN Manager authentication level | Block NTLMv1/LM relay attacks |
| Force audit subcategory | 2.3.2.1 (L1) | Audit: Force audit policy subcategory settings | Enable granular security event logging |

---

## Initial Audit

Audit executed via **Microsoft Security Compliance Toolkit (MSCT)** against the `Windows 11 v25H2 Security Baseline`.

### Tool: Policy Viewer (MSCT)

The MSCT Policy Viewer loads the baseline and compares it against the effective state of the machine, displaying each setting with its expected value (`BASE`) vs actual value (`EffectiveState_MO`).

**Audit scope:** 425 policy items analyzed
**Conflicts identified (Show Only Conflict mode):** 37 items

### Screenshots

| Screenshot | Description |
|-----------|-------------|
| ![Audit baseline loaded](screenshots/audit-initial-baseline.png) | MSCT with Windows 11 v25H2 Security Baseline loaded |
| ![Effective state view](screenshots/audit-effective-state.png) | Effective state column showing actual machine configuration |
| ![Conflicts view](screenshots/audit-conflicts-only.png) | Filtered view showing only the 37 conflicts |

---

## Gap Analysis

Conflicts grouped by category after the initial audit:

### Account & Authentication

| Setting | Issue |
|---------|-------|
| `LockoutBadCount` | Set to 0 — no lockout threshold |
| `MinimumPasswordLength` | Below required minimum |
| `PasswordComplexity` | Disabled |
| `PasswordHistorySize` | Too short |
| `SeInteractiveLogonRight` | Over-permissive |
| `SeNetworkLogonRight` | Over-permissive |
| `SeDenyNetworkLogonRight` | Not configured |
| `SeBackupPrivilege` | Not restricted |
| `SeRestorePrivilege` | Not restricted |

### Services & Features

| Setting | Issue |
|---------|-------|
| `XblAuthManager` | Xbox service running on a workstation |
| `XblGameSave` | Xbox service running |
| `XboxGipSvc` | Xbox service running |
| `XboxNetApiSvc` | Xbox service running |

### Firewall & Network

| Setting | Issue |
|---------|-------|
| `RestrictAnonymous` | Set to 0 — anonymous SAM enumeration allowed |
| `NTLMMinClientSec` | Weak NTLM session security |
| `NTLMMinServerSec` | Weak NTLM session security |

### Audit & Logging

All credential validation, file sharing, removable storage, and session management auditing subcategories were set to `No Audit` instead of the required `Success and Failure`.

### User Account Control

| Setting | Current | Required |
|---------|---------|---------|
| `ConsentPromptBehaviorAdmin` | 5 (elevate without prompt) | 2 (prompt on secure desktop) |
| `ConsentPromptBehaviorUser` | 3 | 0 |
| `TypeOfAdminApprovalMode` | 1 | 2 |

---

## Critical Findings

### Finding 1 — `RestrictAnonymous = 0` ⚠️ CRITICAL

**Scenario:** An attacker on the same network can enumerate all local accounts and shares without any credentials — equivalent to browsing an open company directory.

**Attack surface:**
- Lists all usernames (admin, guest, service accounts)
- Enables targeted credential attacks using real account names

**Risk:** Probability: **High** (network scans are routine) | Severity: **Critical**

---

### Finding 2 — `LockoutBadCount = 0` ⚠️ HIGH

**Scenario:** No lockout policy means unlimited brute-force attempts. An automated script can test millions of password combinations without any throttle.

**Attack surface:**
- Unlimited dictionary attacks
- No rate limiting on authentication attempts

**Risk:** Probability: **Medium** | Severity: **High**

---

### Finding 3 — `PasswordComplexity = 0` ⚠️ HIGH

**Scenario:** Users can set trivially weak passwords (e.g., `123456`, `azerty`). Credential-stealing malware recovers these instantly.

**Risk:** Probability: **Very High** | Severity: **High**

---

### Finding 4 — Audit Credential Validation: Disabled ⚠️ HIGH

**Scenario:** 500 login attempts on your account generate zero alerts. An attacker can probe the system silently with no forensic trace left behind.

**Risk:** Probability: **Medium** | Severity: **High** (no detection possible)

---

### Finding 5 — `ConsentPromptBehaviorAdmin = 5` ⚠️ CRITICAL

**Scenario:** UAC is configured to elevate privileges silently. Malware bundled with a free download automatically obtains admin rights without any user confirmation.

**Risk:** Probability: **Medium** | Severity: **Critical** (full system takeover possible)

---

## Hardening Applied

### 1. `RestrictAnonymous` → 1

**Location:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`

| State | Value |
|-------|-------|
| Before | 0 (anonymous SAM enumeration **allowed**) |
| After | 1 (anonymous SAM enumeration **blocked**) |

**Method:** Local Security Policy → Network access: Do not allow anonymous enumeration of SAM accounts → **Enabled**

**Verification:**
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous"
# Expected: restrictanonymous : 1
```

**Side effects:** None for authenticated users. Network shares continue to work normally. Only anonymous access to system information is blocked.

**Screenshots:**

| Before | After |
|--------|-------|
| ![RestrictAnonymous before](screenshots/restrictanonymous-before.png) | ![RestrictAnonymous after](screenshots/restrictanonymous-after.png) |

![Verification](screenshots/restrictanonymous-verify.png)

---

### 2. `LockoutBadCount` → 10

**Location:** Local Security Policy → Account Lockout Policy

| State | Value |
|-------|-------|
| Before | 0 (account **never** locked) |
| After | 10 (account locked after 10 failed attempts for 30 minutes) |

**Verification:**
```powershell
net accounts
# Account lockout threshold: 10
```

**Side effects:**
- Forgetful users may accidentally lock themselves out
- Protects against all automated brute-force attacks

**Screenshots:**

| Before | After |
|--------|-------|
| ![Lockout before](screenshots/lockout-before.png) | ![Lockout after](screenshots/lockout-after.png) |

![Account locked screen](screenshots/lockout-verify.png)

---

### 3. `PasswordComplexity` → Enabled

**Location:** Local Security Policy → Password Policy

| State | Value |
|-------|-------|
| Before | Disabled |
| After | Enabled (requires uppercase + lowercase + digit + symbol) |

**Side effects:**
- New passwords must meet complexity requirements immediately
- Existing passwords remain valid until next change cycle

**Screenshots:**

| Before | After |
|--------|-------|
| ![PwComplexity before](screenshots/pwcomplexity-before.png) | ![PwComplexity after](screenshots/pwcomplexity-after.png) |

---

### 4. Audit Credential Validation → Success and Failure

**Location:** Local Security Policy → Advanced Audit Policy → Logon/Logoff → Audit Credential Validation

| State | Value |
|-------|-------|
| Before | No Audit |
| After | Success and Failure |

This generates Windows Security Events:
- **Event 4624** — Successful logon
- **Event 4625** — Failed logon attempt

**Side effects:**
- No performance impact
- Log size increases slightly
- Brute-force attacks become detectable via Event Viewer

**Screenshots:**

| Before | After |
|--------|-------|
| ![Audit before](screenshots/audit-cred-before.png) | ![Audit after](screenshots/audit-cred-after.png) |

![Event 4624](screenshots/audit-event-4624.png)
![Event 4625 - failed logon](screenshots/audit-event-4625.png)

---

### 5. `ConsentPromptBehaviorAdmin` → 2 (Secure Desktop Consent)

**Location:** Local Security Policy → User Account Control

| State | Value | Behavior |
|-------|-------|---------|
| Before | 5 | Elevate privileges silently without prompt |
| After | 2 | Prompt for consent on the secure desktop |

**Side effects:**
- Admin must click "Yes" to confirm privilege elevation
- Slight workflow interruption for administrative tasks
- **Prevents silent malware execution with admin rights**

**Screenshots:**

| Before | After |
|--------|-------|
| ![UAC before](screenshots/uac-before.png) | ![UAC after](screenshots/uac-after.png) |

![UAC prompt verification](screenshots/uac-verify.png)

---

## Post-Hardening Validation

### Conformity Comparison

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Total conflicts (MSCT) | 37 | 32 | **−5 conflicts resolved** |
| Reduction rate | — | — | **13.5%** |
| New warnings introduced | 0 | 0 | **No regressions** |

### Attack Surface Impact (Per Remediation)

| Measure | Impact | Attack Vector Blocked |
|---------|--------|----------------------|
| `RestrictAnonymous = 1` | 🔴 Maximum | Network reconnaissance / SAM enumeration |
| `LockoutBadCount = 10` | 🟠 Significant | Automated brute-force (online) |
| `UAC Admin = 2` | 🔴 Critical | Silent malware privilege escalation |
| `PasswordComplexity = 1` | 🟠 High | Weak credential exploitation |
| `Audit enabled` | 🟡 Detection | Any credential-based attack (visibility gain) |

### Screenshots

| Before | After |
|--------|-------|
| ![Audit before hardening](screenshots/msct-before.png) | ![Audit after hardening](screenshots/msct-after.png) |

---

## Manual Security Tests

### Test 1 — Disable Windows Defender via PowerShell

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Result:** ❌ Blocked — `HRESULT 0xc0000142` (Access Denied)

**Observation:** Security policies block execution of the modification command at the OS permission layer, before Defender is even invoked. This demonstrates **defense in depth**: the hardening prevents the command from running, not just its effect.

![Defender disable blocked](screenshots/test-defender.png)

---

### Test 2 — Open a Blocked Port (4444)

```powershell
New-NetFirewallRule -DisplayName "BLOCK_PORT_4444" -Direction Inbound -LocalPort 4444 -Protocol TCP -Action Block
Test-NetConnection -ComputerName localhost -Port 4444
```

**Result:** ❌ `TcpTestSucceeded : False`

**Observation:** Connection attempt to port 4444 failed immediately. No Event ID 5157 was generated because the test used localhost (127.0.0.1) — the Windows Firewall applies looser rules for loopback traffic. Blocking logs would appear for external traffic attempts against active services.

![Port blocked test](screenshots/test-port.png)

---

### Test 3 — Create an Unauthorized Local Account

```powershell
New-LocalUser -Name "testpart4" -Password (ConvertTo-SecureString "passworD123?" -AsPlainText -Force)
```

**Result:** ❌ `New-LocalUser: Access denied`

**Observation:** Account creation was immediately and systematically blocked. The GUI equivalent also triggered a UAC prompt requiring admin credentials. Privilege separation is fully enforced.

![Account creation blocked](screenshots/test-account.png)

---

## Security Maturity Assessment

*Scale: 1 = Very Low | 2 = Low | 3 = Medium | 4 = Good | 5 = Excellent*

| Axis | Before | After | Gain | Notes |
|------|--------|-------|------|-------|
| **Authentication** | 1 | 3 | +2 | Password complexity, minimum length (14+), lockout after 10 attempts |
| **Network** | 2 | 3 | +1 | Anonymous SAM enumeration blocked |
| **System** | 1 | 2 | +1 | UAC hardened to mode 2 (consent prompt) |
| **Monitoring** | 1 | 1 | 0 | Audit configured but not actively reviewed |
| **Global score** | **1/5** | **2/5** | **+1** | Meaningful but modest improvement |

### What Remains "Cosmetic"

Some applied measures have limited real-world impact without supporting processes:

- **`PasswordComplexity = 1`** — `Password123!` satisfies the requirement. Without user education, complexity requirements are easily gamed.
- **Audit Credential Validation** — Logs are generated but if no one reviews them, attacks go undetected.
- **UAC mode 2** — Users who habitually click through UAC prompts without reading them negate the protection.

Only `RestrictAnonymous = 1` provides an unconditional, hard technical block regardless of user behavior.

---

## Recommendations

### Technical
Implement **multi-factor authentication (MFA)** for all administrator and privileged accounts via Windows Hello for Business or a third-party solution. This eliminates the largest remaining attack vector: credential theft.

### Organizational
Establish a **monthly security log review process** with a designated owner and standardized reporting template. Audit data is worthless without a human review cycle.

### Behavioral
Run **quarterly phishing simulations and UAC awareness training**. Users who understand why a prompt appears will engage with it meaningfully rather than clicking through reflexively.

---

## 6-Month Maintenance Plan

### Months 1–2
- Automate weekly compliance check via PowerShell script
- Configure email alerts for critical security events (failed logons, Defender disablement attempts)

### Months 3–4
- Review and tune lockout policy based on help desk call data
- Test configuration restore from a hardening backup

### Months 5–6
- Conduct an internal penetration test to validate controls
- Update baseline to the latest CIS Benchmark release

### Compliance Script (PowerShell)

```powershell
# Weekly compliance check — run via Task Scheduler
$checks = @{
    "RestrictAnonymous"         = { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").RestrictAnonymous -eq 1 }
    "LockoutBadCount"           = { (net accounts | Select-String "lockout threshold").ToString() -match "10" }
    "PasswordComplexity"        = { (net accounts | Select-String "complex").ToString() -notmatch "disabled" }
    "DefenderRealtimeEnabled"   = { (Get-MpPreference).DisableRealtimeMonitoring -eq $false }
}

$results = @()
foreach ($check in $checks.GetEnumerator()) {
    $pass = & $check.Value
    $results += [PSCustomObject]@{ Check = $check.Key; Status = if ($pass) {"PASS"} else {"FAIL"} }
}

$results | Format-Table -AutoSize
$failCount = ($results | Where-Object Status -eq "FAIL").Count
if ($failCount -gt 0) {
    Write-Warning "$failCount check(s) failed — review required"
}
```

---

## File Structure

```
windows-hardening/
├── README.md                    # This document
├── docs/
│   └── baseline-comparison.md  # CIS vs Microsoft Baseline deep-dive
└── screenshots/                 # All audit and remediation screenshots
```

---

*Author: HAMDANI Mohammed | Platform: Windows 11 v25H2 | Frameworks: CIS Benchmark v2.0.0 + MSCT*
