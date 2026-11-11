# Hunt Hypothesis: LOLBAS Execution

## Hunt ID: HUNT-001
**Date**: 2026-11-14
**Analyst**: Satyam Kumar
**Framework**: PEAK (Prepare → Execute → Analyze → Knowledge)

---

## 1. Prepare: Hypothesis Definition

**Hypothesis**: *Adversaries use Living-Off-The-Land Binaries (LOLBAS) — specifically `certutil.exe`, `rundll32.exe`, `mshta.exe`, `regsvr32.exe`, `wmic.exe` — to execute code and evade defenses, because these are signed Microsoft binaries that are rarely blocked.*

**Why This Matters**:
- LOLBAS bypasses application allowlisting
- Signed binaries evade reputation-based detection
- Common in fileless malware and post-exploitation frameworks
- Our current Wazuh rules have limited coverage for LOLBAS behavior

**Expected TTPs**:
| Technique | Description |
|-----------|-------------|
| T1218.011 | Rundll32 proxy execution |
| T1218.005 | Mshta proxy execution |
| T1218.010 | Regsvr32 proxy execution |
| T1105 | Ingress tool transfer (certutil decode) |
| T1059.001 | PowerShell execution (child of LOLBAS) |

---

## 2. Prepare: Data Sources & Scope

| Data Source | Coverage | Fields of Interest |
|-------------|----------|-------------------|
| Sysmon EventID 1 | Process Creation | Image, CommandLine, ParentImage, TargetUserName, IntegrityLevel |
| Sysmon EventID 3 | Network Connection | SourceImage, DestinationIp, DestinationPort |
| Sysmon EventID 7 | Image Load | Image, ImageLoaded |
| Sysmon EventID 10 | Process Access | SourceImage, TargetImage, GrantedAccess |
| Wazuh Rules | Alerts | rule.id, rule.groups, mitre.id |

**Time Range**: Last 7 days (2026-11-07 to 2026-11-14)
**Scope**: All Windows endpoints (win-endpoint)

---

## 3. Prepare: LOLBAS Binaries to Hunt

| Binary | Legitimate Path | Suspicious Indicators |
|--------|-----------------|----------------------|
| `certutil.exe` | `C:\Windows\System32\` | `-decode`, `-encode`, `-urlcache`, `-split`, from non-System32 |
| `rundll32.exe` | `C:\Windows\System32\` | `comsvcs.dll`, `MiniDump`, `#1`, `EntryPoint`, DLL from Temp/AppData |
| `mshta.exe` | `C:\Windows\System32\` | `.hta` from HTTP, `javascript:`, `vbscript:`, from Temp |
| `regsvr32.exe` | `C:\Windows\System32\` | `/s`, `/u`, `/i`, `.dll` from Temp, `scrobj.dll` |
| `wmic.exe` | `C:\Windows\System32\` | `process call create`, `/node:`, from non-System32 |
| `reg.exe` | `C:\Windows\System32\` | `add HKCU\Run`, `add HKLM\Run`, from Temp |

---

## 4. Execute: Queries Run

### Query 1: LOLBAS from Non-Standard Paths
```sql
-- WQL / OpenSearch
event.code:1 AND win.eventdata.image:(*certutil* OR *rundll32* OR *mshta* OR *regsvr32* OR *wmic* OR *reg*)
AND NOT win.eventdata.image:("C:\\Windows\\System32\\*" OR "C:\\Windows\\SysWOW64\\*")
| stats count by win.eventdata.image, win.eventdata.commandLine, win.eventdata.parentImage, win.targetuser
```

**Result**: 3 hits — `certutil.exe` from `%TEMP%`, `rundll32.exe` from `%TEMP%`, `mshta.exe` from `%TEMP%`

### Query 2: certutil -decode Activity
```sql
event.code:1 AND win.eventdata.image:*certutil* AND win.eventdata.commandLine:*decode*
| stats count by win.eventdata.commandLine, win.eventdata.parentImage, win.targetuser, @timestamp
```

**Result**: 1 hit — `certutil.exe -decode C:\Users\labuser\AppData\Local\Temp\payload.b64 C:\Users\labuser\AppData\Local\Temp\payload.ps1`

### Query 3: Child Processes of LOLBAS
```sql
event.code:1 AND win.eventdata.parentImage:(*certutil* OR *rundll32* OR *mshta* OR *regsvr32*)
| stats count by win.eventdata.image, win.eventdata.commandLine, win.eventdata.parentImage, win.targetuser
```

**Result**: 
- `certutil.exe` → `powershell.exe` (PID 4122) with IEX DownloadString
- `rundll32.exe` → (no children, but accessed LSASS)

### Query 4: Network Connections from LOLBAS Children
```sql
event.code:3 AND win.eventdata.sourceImage:*powershell*
| where win.eventdata.parentImage IN (*certutil*, *rundll32*, *mshta*, *regsvr32*)
| stats count by win.eventdata.destinationIp, win.eventdata.destinationPort, win.eventdata.sourceImage
```

**Result**: `powershell.exe` (child of certutil) → `198.51.100.23:443`

### Query 5: Rundll32 + comsvcs.dll (LSASS Dump)
```sql
event.code:1 AND win.eventdata.image:*rundll32* AND win.eventdata.commandLine:*comsvcs.dll*
| stats count by win.eventdata.commandLine, win.targetuser, @timestamp
```

**Result**: `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 1234 C:\Temp\lsass.dmp full`

### Query 6: Sysmon EventID 10 - LSASS Access
```sql
event.code:10 AND win.eventdata.targetImage:*lsass.exe* AND win.eventdata.sourceImage:*rundll32*
| stats count by win.eventdata.sourceImage, win.eventdata.grantedAccess, win.targetuser
```

**Result**: `rundll32.exe` → `lsass.exe` with GrantedAccess=0x1010 (VM_READ | PROCESS_QUERY_LIMITED)

---

## 5. Analyze: Findings Summary

| Finding | Details | MITRE | Confidence |
|---------|---------|-------|------------|
| **certutil decode → PowerShell** | `certutil -decode` dropped payload to Temp, executed via PowerShell with IEX DownloadString to 198.51.100.23 | T1105, T1059.001 | HIGH |
| **rundll32 comsvcs.dll MiniDump** | `rundll32.exe` used to dump LSASS memory via comsvcs.dll export | T1218.011, T1003.001 | HIGH |
| **PowerShell C2 beacon** | PowerShell (child of certutil) beaconing to 198.51.100.23:443 every 60s | T1071.001 | HIGH |

**Attack Chain Reconstructed**:
```
Initial Access (simulated)
    ↓
certutil.exe -decode payload.b64 payload.ps1  (T1105)
    ↓
powershell.exe -enc <payload.ps1>              (T1059.001)
    ├─→ IEX DownloadString → 198.51.100.23    (T1105)
    ├─→ C2 Beacon HTTPS every 60s              (T1071.001)
    └─→ rundll32.exe comsvcs.dll MiniDump     (T1218.011, T1003.001)
```

---

## 6. Knowledge: Detection Rules Created

| Rule ID | Name | Platform | Technique |
|---------|------|----------|-----------|
| DET-001 | PowerShell Encoded Command + Network | Wazuh, Splunk, Suricata, Sigma | T1059.001, T1071.001 |
| DET-006 | LOLBAS Rundll32 Proxy Execution | Wazuh, Splunk, Suricata, Sigma | T1218.011 |

---

## 7. Knowledge: MITRE Coverage Update

| Technique | Previous Coverage | New Coverage | Evidence |
|-----------|------------------|--------------|----------|
| T1218.011 | Level 0 (none) | Level 2 (tuned rule + hunt validated) | DET-006, HUNT-001 |
| T1105 | Level 1 (basic) | Level 2 (composite with certutil) | DET-001, HUNT-001 |
| T1059.001 | Level 1 (basic) | Level 3 (composite + network) | DET-001, HUNT-001 |
| T1071.001 | Level 0 (none) | Level 2 (Suricata + Wazuh) | DET-001, HUNT-001 |

---

## 8. Lessons Learned

1. **certutil is a powerful LOLBAS** — `-decode` + PowerShell child is a reliable pattern
2. **rundll32 + comsvcs.dll** is the most common LSASS dump technique — catch at process creation (EventID 1) not just memory access (EventID 10)
3. **Parent-child correlation is key** — LOLBAS alone is noisy; LOLBAS → PowerShell → Network is high fidelity
4. **Suricata HTTP User-Agent** catches `rundll32`/`certutil` as HTTP clients (C2)

---

## 9. Next Hunt Seeds

- Hunt for `mshta.exe` executing remote HTA (T1218.005)
- Hunt for `regsvr32.exe /s /u /i:http... scrobj.dll` (T1218.010)
- Hunt for `wmic.exe process call create` lateral movement (T1047)

---

**Hunt Status**: ✅ COMPLETE
**Analyst**: Satyam Kumar
**Date**: 2026-11-14