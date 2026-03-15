# Security Hardening Portfolio

A comprehensive security hardening study covering both Windows and Linux environments, based on industry-standard frameworks (CIS Benchmarks and Microsoft Security Baselines).

---

## Projects

| Project | Platform | Framework | Score Achieved |
|---------|----------|-----------|----------------|
| [Windows Hardening](./windows-hardening/) | Windows 11 | CIS Benchmark v2.0.0 + MSCT | 5 critical gaps resolved |
| [Linux Hardening](./linux-hardening/) | Debian 12 | CIS Benchmark + Lynis | 46% → 51% conformity |

---

## Methodology

Both projects follow the same structured approach:

```
Audit → Gap Analysis → Prioritization → Remediation → Re-audit → Roadmap
```

1. **Initial Audit** — Establish baseline using automated tools
2. **Gap Analysis** — Categorize and score each non-conformity
3. **Threat Modeling** — Assign exploitation scenarios to each gap
4. **Targeted Hardening** — Apply remediations with documented before/after
5. **Post-Audit Validation** — Measure improvement with the same tools
6. **Operational Roadmap** — Define maintenance schedule and next steps

---

## Key Takeaways

- Security hardening is a **continuous process**, not a one-time project
- CIS Benchmarks provide **community consensus** while Microsoft Baselines optimize for **ecosystem compatibility**
- Measuring before and after is essential — **you can't improve what you don't measure**
- Balancing security strictness with usability is a core skill: Level 1 CIS profiles offer the best security/friction ratio for standard workstations

---

*Author: HAMDANI Mohammed*
