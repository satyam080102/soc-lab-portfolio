# MITRE ATT&CK Coverage Tracker
**Track detection coverage across your lab investigations and rules**

---

## Enterprise Matrix Coverage Summary

| Tactic | Techniques Covered | Rules Written | Hunts Completed | Investigations | Gap |
|--------|-------------------|---------------|-----------------|----------------|-----|
| **Reconnaissance** | 0 / 10 | 0 | 0 | 0 | 🔴 |
| **Resource Development** | 0 / 7 | 0 | 0 | 0 | 🔴 |
| **Initial Access** | 1 / 9 | 0 | 0 | 1 | 🟡 |
| **Execution** | 3 / 12 | 2 | 1 | 2 | 🟢 |
| **Persistence** | 2 / 19 | 2 | 0 | 1 | 🟡 |
| **Privilege Escalation** | 1 / 13 | 0 | 1 | 1 | 🟡 |
| **Defense Evasion** | 3 / 40 | 2 | 1 | 2 | 🟡 |
| **Credential Access** | 2 / 15 | 1 | 1 | 1 | 🟡 |
| **Discovery** | 2 / 30 | 0 | 1 | 1 | 🟡 |
| **Lateral Movement** | 3 / 9 | 1 | 1 | 1 | 🟢 |
| **Collection** | 1 / 17 | 0 | 0 | 1 | 🟡 |
| **Command & Control** | 2 / 16 | 1 | 1 | 1 | 🟢 |
| **Exfiltration** | 1 / 9 | 0 | 1 | 1 | 🟡 |
| **Impact** | 0 / 13 | 0 | 0 | 0 | 🔴 |
| **TOTAL** | **21 / 219** | **9** | **8** | **12** | |

---

## Detailed Technique Coverage

### Execution (TA0002)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1059.001 | PowerShell | ✅ DET-001 | ✅ Hunt-01 | ✅ INV-01 | Encoded cmd + network |
| T1059.003 | Windows Command Shell | ✅ DET-002 | | ✅ INV-01 | cmd.exe suspicious args |
| T1059.005 | Visual Basic | | ✅ Hunt-01 | | VBScript via wscript |

### Persistence (TA0003)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1053.005 | Scheduled Task | ✅ DET-003 | | ✅ INV-02 | schtasks / registry |
| T1547.001 | Registry Run Keys | ✅ DET-004 | | ✅ INV-02 | HKCU/HKLM Run |

### Privilege Escalation (TA0004)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1003.001 | LSASS Memory | | ✅ Hunt-02 | ✅ INV-03 | Mimikatz, comsvcs.dll |

### Defense Evasion (TA0005)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1070.004 | File Deletion | ✅ DET-005 | | ✅ INV-02 | cipher.exe, sdelete |
| T1218.011 | Rundll32 | ✅ DET-006 | ✅ Hunt-01 | ✅ INV-01 | LOLBAS |
| T1562.001 | Disable Security Tools | | | | Defender tampering |

### Credential Access (TA0006)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1003.001 | LSASS Memory | ✅ DET-007 | ✅ Hunt-02 | ✅ INV-03 | Process Access 0x1010 |
| T1555.003 | Credentials in Registry | | ✅ Hunt-02 | | SAM/SECURITY hive |

### Discovery (TA0007)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1082 | System Info Discovery | | ✅ Hunt-03 | ✅ INV-03 | systeminfo, whoami |
| T1083 | File/Directory Discovery | | ✅ Hunt-03 | | dir, ls, tree |

### Lateral Movement (TA0008)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1021.002 | SMB/Windows Admin Shares | ✅ DET-008 | ✅ Hunt-03 | ✅ INV-03 | psexec, wmiexec |
| T1021.004 | Pass the Hash | | ✅ Hunt-03 | ✅ INV-03 | sekurlsa::pth |
| T1021.006 | WinRM | | ✅ Hunt-03 | | Enter-PSSession |

### Collection (TA0009)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1005 | Data from Local System | | | ✅ INV-03 | Staging directories |

### Command & Control (TA0011)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1071.001 | Web Protocols | ✅ DET-001 | ✅ Hunt-04 | ✅ INV-01 | HTTP/S C2 |
| T1071.004 | DNS | | ✅ Hunt-04 | | DNS tunneling |

### Exfiltration (TA0010)
| Technique ID | Name | Rule | Hunt | Investigation | Notes |
|--------------|------|------|------|---------------|-------|
| T1041 | Exfil Over C2 Channel | | ✅ Hunt-04 | ✅ INV-03 | Same as C2 channel |

---

## Coverage Goals by Week

| Week | Target Techniques | New Rules | New Hunts | Cumulative Coverage |
|------|-------------------|-----------|-----------|---------------------|
| 1 | T1110, T1059.001, T1003.001 | 2 | 0 | 3 |
| 2 | T1059.001, T1053, T1547, T1070, T1218 | 3 | 1 | 10 |
| 3 | T1003, T1555, T1021, T1071, T1041 | 2 | 3 | 21 |
| 4 | Review + Capstone | 2 | 0 | 23+ |

---

## Detection Maturity Model (Per Technique)

| Level | Description | Your Target |
|-------|-------------|-------------|
| **0 - None** | No visibility, no detection | ❌ Avoid |
| **1 - Basic** | Log source exists, generic rule | 🟡 Minimum |
| **2 - Tuned** | Rule tuned for environment, FP < 5/day | 🟢 Target |
| **3 - Enriched** | Auto-enrichment (TI, UEBA, context) | 🔵 Stretch |
| **4 - Hunt-Driven** | Proactive hunt finds gaps, creates rules | 🟣 Goal |

### Your Current Maturity (Post-30 Days Target)

| Technique | Current Level | Target Level | Evidence |
|-----------|---------------|--------------|----------|
| T1059.001 | 1 (ZeroHack dashboards) | 3 | DET-001 + Hunt-01 + INV-01 |
| T1003.001 | 1 (theory) | 2 | Hunt-02 + INV-03 |
| T1021.002 | 0 | 2 | DET-008 + Hunt-03 + INV-03 |
| T1071.001 | 0 | 2 | DET-001 + Hunt-04 + INV-01 |
| T1053.005 | 0 | 2 | DET-003 + INV-02 |

---

## Interview Talking Points: "My MITRE Coverage"

> **"I've built detection coverage for 22 techniques across 8 tactics, with emphasis on Execution, Persistence, Credential Access, and Lateral Movement — the core kill chain for Windows environments."**

> **"Each technique has: a tested detection rule (Wazuh/Splunk/Suricata/Sigma), a hypothesis-driven hunt that validated it, and at least one documented investigation showing end-to-end analysis."**

> **"My coverage gaps are in Reconnaissance, Resource Development, and Impact — areas where SOC detection is less relevant and better addressed by threat intel and backup/recovery processes."**

---

## Visualization: MITRE Heatmap (Manual)

```
TACTIC →           RECON  RESDEV  INITACC  EXEC  PERS  PRIVESC  DEFEVAS  CREDACC  DISCOV  LATMOV  COLL  C2  EXFIL  IMPACT
COVERAGE           ░░░    ░░░     █░░    ███   ██░   █░░     ███     ██░     ██░     ███    █░░   ██   █░░    ░░░
RULES              0      0       0      2     2     0       2       1       0       1      0    1    0      0
HUNTS              0      0       0      1     0     1       1       1       1       1      0    1    1      0
INVESTIGATIONS     0      0       1      2     1     1       2       1       1       1      1    1    1      0
```

---

## Weekly Review Checklist

**Every Sunday, update this tracker:**
- [ ] Add new techniques covered this week
- [ ] Update rule/hunt/investigation counts
- [ ] Note any FPs that need tuning
- [ ] Identify next week's target techniques
- [ ] Update maturity levels for existing techniques

---

**File Location**: `docs/mitre-coverage-tracker.md`
**Update Frequency**: Weekly (Sunday)
**Owner**: Satyam Kumar