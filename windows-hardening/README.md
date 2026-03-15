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

### CIS Microsoft Windows 11 Stand-alone Benchmark v2.0.0

| Attribute | Details |
|-----------|---------|
| **Origin** | Center for Internet Security — independent non-profit, community-consensus model |
| **Philosophy** | Prescriptive and strict; maximizes security posture |
| **Level 1** | Low impact, applicable to any workstation without breaking functionality |
| **Level 2** | High security, may require extensive testing before deployment |

### Microsoft Security Compliance Toolkit (MSCT) — Windows 11 v25H2

| Attribute | Details |
|-----------|---------|
| **Origin** | Microsoft — developed and validated internally by the security team |
| **Philosophy** | Pragmatic; balances security with product compatibility |
| **Format** | Pre-configured Group Policy Objects (GPOs) |

### Key Differences

| Dimension | CIS Benchmark | Microsoft Baseline |
|-----------|--------------|-------------------|
| Authority | Independent community experts | OS vendor |
| Strictness | Higher (especially Level 2) | Moderate |
| Compatibility focus | Low | High |
| Deployment method | Manual or scripted | GPO / MSCT tool |

### 5 Common Rules

| Rule | CIS Reference | Objective |
|------|-------------|-----------|
| Rename admin account | 2.3.1.4 (L1) | Prevent targeted brute-force on known account names |
| Max password age | 1.1.2 (L1) | Force regular credential rotation |
| Account lockout threshold | 1.2.2 (L1) | Block dictionary and brute-force attacks |
| LAN Manager auth level | 2.3.11.7 (L1) | Block NTLMv1/LM relay attacks |
| Force audit subcategory | 2.3.2.1 (L1) | Enable granular security event logging |

![CIS rule — max password age](screenshots/02-cis-rule-max-password-age.png)

![CIS rule — rename administrator](screenshots/03-cis-rule-rename-admin.png)

![CIS rule — lockout threshold](screenshots/04-cis-rule-lockout-threshold.png)

![CIS rule — NTLM auth level](screenshots/05-cis-rule-ntlm-auth-level.png)

![CIS rule — audit subcategory](screenshots/06-cis-rule-audit-subcategory.png)

---

## Initial Audit

Audit executed via **MSCT** against `Windows 11 v25H2 Security Baseline` — 425 policy items analyzed, **37 conflicts** identified.

![MSCT — Policy Viewer with baseline loaded](screenshots/01-cis-benchmark-policy-viewer.png)

![MSCT — Effective state column](screenshots/08-audit-effective-state.png)

![MSCT — Show only conflict (37 items)](screenshots/09-audit-conflicts-only-37.png)

---

## Gap Analysis

![Gap analysis — categories](screenshots/10-gap-analysis-categories.png)

![Zoom — RestrictAnonymous and LockoutBadCount gaps](screenshots/11-gap-restrictanonymous-lockout-zoom.png)

| Category | Settings in conflict |
|----------|---------------------|
| **Account & Authentication** | LockoutBadCount, MinimumPasswordLength, PasswordComplexity, PasswordHistorySize, SeInteractiveLogonRight, SeNetworkLogonRight, SeDenyNetworkLogonRight |
| **Services** | XblAuthManager, XblGameSave, XboxGipSvc, XboxNetApiSvc |
| **Firewall & Network** | RestrictAnonymous, NTLMMinClientSec, NTLMMinServerSec |
| **Audit & Logging** | All subcategories set to No Audit |
| **UAC** | ConsentPromptBehaviorAdmin = 5, ConsentPromptBehaviorUser, TypeOfAdminApprovalMode |

---

## Critical Findings

### 1 — `RestrictAnonymous = 0` ⚠️ CRITICAL

An attacker on the same network can enumerate all local accounts without credentials — equivalent to an open company directory. Enables targeted credential attacks using real account names.

**Risk:** Probability: High | Severity: Critical

### 2 — `LockoutBadCount = 0` ⚠️ HIGH

No lockout policy — automated scripts can test unlimited password combinations with no throttle.

**Risk:** Probability: Medium | Severity: High

### 3 — `PasswordComplexity = 0` ⚠️ HIGH

Users can set trivially weak passwords (`123456`, `azerty`). Credential-stealing malware recovers these instantly.

**Risk:** Probability: Very High | Severity: High

### 4 — Audit Credential Validation: Disabled ⚠️ HIGH

500 login attempts generate zero alerts. No forensic trace exists after an attack.

**Risk:** Probability: Medium | Severity: High

### 5 — `ConsentPromptBehaviorAdmin = 5` ⚠️ CRITICAL

UAC elevates privileges silently. Malware bundled with any download automatically gets admin rights.

**Risk:** Probability: Medium | Severity: Critical

---

## Hardening Applied

### 1. `RestrictAnonymous` → 1

| | Value |
|-|-------|
| Before | 0 — anonymous SAM enumeration **allowed** |
| After | 1 — anonymous SAM enumeration **blocked** |

**Before:**
![RestrictAnonymous before — Désactivé](screenshots/12-restrictanonymous-before.png)

**After:**
![RestrictAnonymous after — Activé](screenshots/13-restrictanonymous-after.png)

**Verification (PowerShell):**
![PowerShell — restrictanonymous : 1](screenshots/14-restrictanonymous-powershell-verify.png)

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous"
# restrictanonymous : 1
```

---

### 2. `LockoutBadCount` → 10

| | Value |
|-|-------|
| Before | 0 — account **never** locked |
| After | 10 — locked after 10 failed attempts |

**Before:**
![LockoutBadCount before — value 0](screenshots/15-lockoutbadcount-before.png)

**After:**
![LockoutBadCount after — value 10](screenshots/16-lockoutbadcount-after.png)

**Account locked (live test):**
![Account locked screen](screenshots/17-lockoutbadcount-account-locked-screen.jpeg)

---

### 3. `PasswordComplexity` → Enabled

| | Value |
|-|-------|
| Before | Disabled |
| After | Enabled — uppercase + lowercase + digit + symbol required |

**Before:**
![PasswordComplexity before — Désactivé](screenshots/18-passwordcomplexity-before.png)

**After:**
![PasswordComplexity after — Activé](screenshots/19-passwordcomplexity-after.png)

**Weak password rejected:**
![Error — password does not meet complexity requirements](screenshots/20-passwordcomplexity-error-weak-password.png)

---

### 4. Audit Credential Validation → Success and Failure

| | Value |
|-|-------|
| Before | No Audit |
| After | Success and Failure |

**Before:**
![Audit Credential Validation before — no checkboxes](screenshots/21-audit-credential-validation-before.png)

**After:**
![Audit Credential Validation after — both checked](screenshots/22-audit-credential-validation-after.png)

**Event 4624 — Successful logon now logged:**
![Event 4624 — logon success](screenshots/23-audit-event-4624-logon-success.png)

**Event 4625 — Failed logon now logged:**
![Event 4625 — logon failure](screenshots/24-audit-event-4625-logon-failed.png)

---

### 5. `ConsentPromptBehaviorAdmin` → 2

| | Value | Behavior |
|-|-------|---------|
| Before | 5 | Elevate silently without prompt |
| After | 2 | Prompt for consent on secure desktop |

**Before:**
![UAC Admin before — élever sans invite](screenshots/25-uac-admin-before.png)

**After:**
![UAC Admin after — demande consentement bureau sécurisé](screenshots/26-uac-admin-after.png)

**UAC prompt now appears:**
![UAC consent prompt for PowerShell](screenshots/27-uac-admin-powershell-prompt.png)

---

## Post-Hardening Validation

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Total conflicts (MSCT) | 37 | 32 | **−5 resolved** |
| Reduction rate | — | — | **13.5%** |
| New warnings introduced | 0 | 0 | **No regressions** |

**MSCT — 32 conflicts remaining:**
![MSCT post-hardening — 32 conflicts](screenshots/28-post-audit-msct-32-conflicts.png)

**Before / After comparison:**
![Post-audit summary](screenshots/29-post-audit-summary-before-after.png)

---

## Manual Security Tests

### Test 1 — Disable Windows Defender

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

❌ **Blocked** — `HRESULT 0xc0000142` (Access Denied)

![Defender disable — blocked by system](screenshots/30-test-defender-disable-blocked.png)

---

### Test 2 — Connect to Blocked Port 4444

```powershell
Test-NetConnection -ComputerName localhost -Port 4444
```

❌ **Blocked** — `TcpTestSucceeded : False`

![Port 4444 — TcpTestSucceeded False](screenshots/31-test-port-4444-blocked.png)

---

### Test 3 — Create Unauthorized Local Account

```powershell
New-LocalUser -Name "testpart4" -Password (ConvertTo-SecureString "passworD123?" -AsPlainText -Force)
```

❌ **Blocked** — `AccessDeniedException`

**PowerShell:**
![Account creation blocked — PowerShell](screenshots/32-test-account-creation-blocked-powershell.png)

**GUI:**
![Account creation blocked — GUI UAC prompt](screenshots/33-test-account-creation-blocked-gui.png)

---

## Security Maturity Assessment

*Scale: 1 = Very Low → 5 = Excellent*

| Axis | Before | After | Gain |
|------|--------|-------|------|
| Authentication | 1 | 3 | +2 |
| Network | 2 | 3 | +1 |
| System | 1 | 2 | +1 |
| Monitoring | 1 | 1 | 0 |
| **Global** | **1/5** | **2/5** | **+1** |

---

## Recommendations

**Technical:** Implement MFA for all administrator accounts via Windows Hello for Business.

**Organizational:** Monthly security log review with a designated owner and reporting template.

**Behavioral:** Quarterly phishing simulations and UAC awareness training.

---

## 6-Month Maintenance Plan

| Period | Action |
|--------|--------|
| Months 1–2 | Automate weekly compliance check; configure email alerts for critical events |
| Months 3–4 | Review lockout policy based on help desk data; test restore from config backup |
| Months 5–6 | Internal penetration test; update to latest CIS Benchmark release |

```powershell
# Weekly compliance check
$checks = @{
    "RestrictAnonymous"       = { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").RestrictAnonymous -eq 1 }
    "LockoutBadCount"         = { (net accounts | Select-String "lockout threshold").ToString() -match "10" }
    "PasswordComplexity"      = { (net accounts | Select-String "complex").ToString() -notmatch "disabled" }
    "DefenderRealtimeEnabled" = { (Get-MpPreference).DisableRealtimeMonitoring -eq $false }
}
$results = @()
foreach ($check in $checks.GetEnumerator()) {
    $pass = & $check.Value
    $results += [PSCustomObject]@{ Check = $check.Key; Status = if ($pass) {"PASS"} else {"FAIL"} }
}
$results | Format-Table -AutoSize
```

---

*Author: HAMDANI Mohammed | Platform: Windows 11 v25H2 | Frameworks: CIS Benchmark v2.0.0 + MSCT*
