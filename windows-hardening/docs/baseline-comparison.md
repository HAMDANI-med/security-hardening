# CIS vs Microsoft Baseline — Deep Dive Comparison

## Overview

When hardening a Windows 11 workstation, two authoritative frameworks are available:
- **CIS Microsoft Windows 11 Stand-alone Benchmark v2.0.0** — community-driven, prescriptive
- **Microsoft Security Compliance Toolkit (MSCT) Windows 11 v25H2** — vendor-driven, pragmatic

This document provides a detailed comparison to help decide when to use each.

---

## Authority and Trust Model

### CIS Benchmark
The Center for Internet Security is a non-profit organization that operates on a **consensus model**: security experts from across industries contribute, debate, and validate every recommendation. This independence means CIS recommendations are:
- Vendor-agnostic where possible
- Battle-tested across diverse environments
- Widely accepted in compliance frameworks (PCI-DSS, HIPAA, SOC 2)

### Microsoft Baseline
Microsoft's baselines are produced internally by their security engineering teams. They are tested specifically against Microsoft's own products and services, meaning they:
- Guarantee compatibility with Active Directory, Defender, and Microsoft 365
- May be more conservative in areas where CIS would recommend stricter settings
- Are updated alongside Windows releases and fully integrated into MSCT tooling

---

## Philosophy

| CIS Benchmark | Microsoft Baseline |
|--------------|-------------------|
| Maximize security posture | Balance security with operational usability |
| Two levels: L1 (safe) and L2 (strict) | Single comprehensive baseline |
| Some rules may break compatibility | Designed to deploy without breaking anything |
| Ideal for hardened, controlled environments | Ideal for managed enterprise rollout |

---

## Rules Comparison

### Password Policy

**CIS 1.1.2 (L1) — Maximum password age ≤ 365 days, not 0**

CIS rationale: The longer a password remains valid, the higher the chance it has been compromised. Setting it to 0 (never expires) is explicitly called out as a major security risk — a compromised password would remain usable indefinitely.

**Microsoft Baseline equivalent:** Maximum password age

Both agree on the need for expiry, but Microsoft's value is calibrated around enterprise helpdesk capacity (more frequent rotation increases support load).

---

### Account Lockout

**CIS 1.2.2 (L1) — Account lockout threshold ≤ 5, not 0**

CIS recommends a maximum of 5 attempts before lockout. This eliminates online brute-force entirely but increases the risk of accidental self-lockout.

**This project used 10 instead of 5** — a deliberate deviation to reduce friction on a non-domain workstation where the user is also the admin and cannot easily self-unlock.

*Takeaway: Always weigh the theoretical optimal against the operational context. A rule that causes frequent lockouts will get disabled.*

---

### Administrator Account Rename

**CIS 2.3.1.4 (L1) — Rename the built-in Administrator account**

The built-in Administrator account has a fixed, well-known SID (`S-1-5-21-...-500`). Renaming the account provides minimal protection if an attacker can enumerate SIDs directly. CIS acknowledges this limitation explicitly:

> *"Even if you rename the Administrator account, an attacker could launch a brute-force attack by using the SID to log on."*

This is an example of a rule that is **easy to apply** but provides **marginal security benefit** — included in Level 1 for defense in depth, not as a primary control.

---

### LAN Manager Authentication Level

**CIS 2.3.11.7 (L1) — Send NTLMv2 only, refuse LM & NTLM**

LAN Manager (LM) and NTLMv1 are legacy protocols with well-documented weaknesses:
- LM hashes can be cracked in seconds with rainbow tables
- NTLMv1 is vulnerable to relay attacks

Both CIS and Microsoft agree: only NTLMv2 should be accepted in modern environments.

---

### Force Audit Subcategory Settings

**CIS 2.3.2.1 (L1) — Force audit policy subcategory settings**

Before Windows Vista, audit policy was configured at the category level (coarse). Since Vista, subcategory-level configuration provides far more granularity. This setting ensures the new subcategory settings take precedence — a prerequisite for all other audit configuration to work correctly.

**This should always be the first audit setting applied.** Without it, other audit configurations may be silently overridden.

---

## When to Use Each Framework

| Scenario | Recommended Framework |
|---------|----------------------|
| Standalone workstation, no domain | CIS Level 1 as primary |
| Domain-joined enterprise workstation | Microsoft Baseline via GPO |
| High-security server / PCI-DSS scope | CIS Level 2 |
| Mixed environment, want easy rollout | MSCT + CIS Level 1 overlap |
| Compliance audit (ISO 27001, SOC 2) | CIS Benchmark (industry-recognized) |

---

## Practical Decision Framework

When a rule exists in both frameworks but with different values, use this logic:

1. **If the gap is small** (e.g., lockout after 5 vs 10): Use the stricter value unless you have evidence of operational issues
2. **If the gap is large** (e.g., a rule that disables a required feature): Apply the less strict value with a documented risk acceptance
3. **If a rule exists only in CIS**: Evaluate whether the added protection justifies the compatibility risk
4. **If a rule exists only in Microsoft**: Apply it — the vendor knows their product's edge cases

---

*This comparison is specific to Windows 11 v25H2 and CIS Benchmark v2.0.0.*
