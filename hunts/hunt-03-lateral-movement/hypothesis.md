# Hunt Hypothesis: Lateral Movement (SMB, WMI, WinRM)

## Hunt ID: HUNT-003
**Date**: 2026-11-18
**Analyst**: Satyam Kumar
**Framework**: PEAK (Prepare → Execute → Analyze → Knowledge)

---

## 1. Prepare: Hypothesis Definition

**Hypothesis**: *Adversaries with valid credentials will use SMB (psexec, admin shares), WMI (wmic, wmiexec), and WinRM (Enter-PSSession, Invoke-Command) for lateral movement to domain controllers and high-value servers.*

**Why This Matters**:
- Lateral movement is how adversaries reach crown jewels
- SMB is most common; WMI/WinRM are stealthier
- Pass-the-Hash/Pass-the-Ticket leave distinct logon patterns
- Our detection had gaps for WMI/WinRM lateral

**Expected TTPs**:
| Technique | Description |
|-----------|-------------|
| T1021.002 | SMB/Windows Admin Shares (psexec, sc.exe, admin$) |
| T1021.004 | Pass the Hash |
| T1021.006 | WinRM (Enter-PSSession, Invoke-Command) |
| T1047 | WMI (wmic, wmiprvse.exe spawning cmd/powershell) |

---

## 2. Prepare: Data Sources

| Source | Events | Key Fields |
|--------|--------|------------|
| Windows Security | 4624 (Logon), 4697 (Service), 5145 (Share) | LogonType, TargetUserName, IpAddress, ServiceName, ShareName |
| Sysmon | 1 (Process), 3 (Network), 22 (DNS) | Image, ParentImage, DestinationIp, SourceImage |
| Suricata | SMB, DCERPC | smb_service_name, smb_share, dcerpc_opnum |

---

## 3. Execute: Queries Run

### Query 1: Admin Logon Type 3 from Non-Mgmt Host
```sql
event.code:4624 AND win.eventdata.logonType:3 AND win.eventdata.targetUserName:administrator
AND NOT win.eventdata.workstationName:(admin-ws OR mgmt-ws OR bastion)
| stats count by win.eventdata.ipAddress, win.eventdata.workstationName, win.eventdata.targetUserName
```

**Result**: 1 hit — IP 192.168.56.20 (win-endpoint), workstation: WIN-ENDPOINT, user: administrator

### Query 2: SMB Service Creation (PsExec)
```sql
event.code:4697 AND win.eventdata.serviceName:(PSEXESVC OR PAExec)
| stats count by win.eventdata.serviceName, win.eventdata.serviceFileName, win.targetuser
```

**Result**: 1 hit — PSEXESVC, `C:\Windows\PSEXESVC.exe`, user: administrator

### Query 3: WMI Lateral (wmiprvse.exe spawning cmd/powershell)
```sql
event.code:1 AND win.eventdata.parentImage:*wmiprvse.exe*
AND win.eventdata.image:(*cmd.exe* OR *powershell.exe*)
| stats count by win.eventdata.image, win.eventdata.commandLine, win.eventdata.parentImage
```

**Result**: 1 hit — `wmiprvse.exe` → `cmd.exe /c whoami`

### Query 4: WinRM (wsmprovhost.exe spawning shell)
```sql
event.code:1 AND win.eventdata.parentImage:*wsmprovhost.exe*
AND win.eventdata.image:(*cmd.exe* OR *powershell.exe*)
| stats count by win.eventdata.image, win.eventdata.commandLine
```

**Result**: 1 hit — `wsmprovhost.exe` → `powershell.exe -enc <base64>`

### Query 5: Admin Share Access (C$, ADMIN$, IPC$)
```sql
event.code:5145 AND win.eventdata.shareName:(C$ OR ADMIN$ OR IPC$)
| stats count by win.eventdata.ipAddress, win.eventdata.shareName, win.eventdata.targetUserName
```

**Result**: Multiple — IPC$ (RPC), ADMIN$ (psexec), C$ (file copy)

---

## 4. Analyze: Attack Chain

```
Compromised Endpoint (192.168.56.20)
    │
    ├─→ SMB: psexec \\DC -u admin -p <hash> → PSEXESVC on DC
    │       ↓
    │       Logon Type 3 (admin) from WIN-ENDPOINT
    │
    ├─→ WMI: wmic /node:DC process call create "cmd"
    │       ↓
    │       wmiprvse.exe → cmd.exe on DC
    │
    └─→ WinRM: Enter-PSSession -ComputerName DC
            ↓
            wsmprovhost.exe → powershell.exe on DC
```

---

## 5. Knowledge: Detection Rule Created

| Rule ID | Name | Platform | Technique |
|---------|------|----------|-----------|
| DET-008 | SMB Lateral Movement | Wazuh, Splunk, Suricata, Sigma | T1021.002, T1021.004 |

---

## 6. MITRE Coverage Update

| Technique | Previous | New | Evidence |
|-----------|----------|-----|----------|
| T1021.002 | Level 0 | Level 2 | DET-008, HUNT-003 |
| T1021.004 | Level 0 | Level 2 | DET-008, HUNT-003 |
| T1021.006 | Level 0 | Level 1 (hunted) | HUNT-003 |
| T1047 | Level 0 | Level 1 (hunted) | HUNT-003 |

---

**Hunt Status**: ✅ COMPLETE
**Analyst**: Satyam Kumar
**Date**: 2026-11-18