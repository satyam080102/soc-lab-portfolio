# Detection Rule: LSASS Memory Access

## 📋 Rule Metadata

| Field | Value |
|-------|-------|
| **Rule ID** | DET-007 |
| **Rule Name** | LSASS Memory Access (Credential Dumping) |
| **Author** | Satyam Kumar |
| **Date Created** | 2026-11-15 |
| **Last Updated** | 2026-11-25 |
| **Status** | PRODUCTION |
| **Platform** | Wazuh, Splunk, Sigma |
| **Severity** | CRITICAL |

---

## 1. Threat Context

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory |

### Threat Scenario
Adversaries access LSASS (Local Security Authority Subsystem Service) process memory to extract credentials (NTLM hashes, Kerberos tickets, clear-text passwords). Tools: Mimikatz, comsvcs.dll, procdump, sqldumper, werfault.

---

## 2. Rule Logic

### Wazuh Rule
```xml
<!-- File: rule.wazuh.xml -->
<group name="credential_access,lsass">
  <rule id="100014" level="15">
    <if_sid>92760</if_sid>
    <field name="win.eventdata.targetImage">.*\\lsass\.exe</field>
    <field name="win.eventdata.grantedAccess">(0x1010|0x1fffff|0x001f0fff|0x000f0fff)</field>
    <description>LSASS memory access with sensitive permissions (T1003.001)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <rule id="100015" level="14">
    <if_sid>92760</if_sid>
    <field name="win.eventdata.targetImage">.*\\lsass\.exe</field>
    <field name="win.eventdata.sourceImage">.*\\(mimikatz|procdump|sqldumper|werfault|comsvcs|rundll32)\.exe</field>
    <description>Known credential dumping tool accessing LSASS (T1003.001)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <rule id="100016" level="13">
    <if_sid>92760</if_sid>
    <field name="win.eventdata.targetImage">.*\\lsass\.exe</field>
    <field name="win.eventdata.sourceImage">.*\\(Temp|AppData|Public|ProgramData|Downloads)\\.*\.exe</field>
    <description>LSASS accessed by binary from suspicious path (T1003.001)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
</group>
```

### CDB Allowlist (Legitimate EDR/AV)
```cdb
# File: cdb/lists/lsass-allowlist.cdb
C:\Program Files\Windows Defender\MsMpEng.exe:defender
C:\Program Files\EDR\agent.exe:edr
C:\Program Files\CrowdStrike\falcon.exe:crowdstrike
C:\Program Files\SentinelOne\SentinelAgent.exe:sentinelone
```

### Splunk SPL
```spl
# File: rule.spl
index=winevents sourcetype=xmlwineventlog EventCode=10
| where like(TargetImage, "%lsass.exe")
| where GrantedAccess IN ("0x1010","0x1fffff","0x001f0fff","0x000f0fff")
| where NOT like(SourceImage, "%MsMpEng.exe") AND NOT like(SourceImage, "%falcon.exe") AND NOT like(SourceImage, "%SentinelAgent.exe")
| eval severity="CRITICAL", mitre="T1003.001"
| table _time, host, SourceImage, TargetImage, GrantedAccess, SourceProcessId, TargetProcessId, severity, mitre
```

### Sigma Rule
```yaml
# File: rule.sigma.yml
title: LSASS Memory Access for Credential Dumping
id: f7890123-4567-89ab-cdef-789012345678
status: test
description: Detects process access to LSASS with sensitive permissions indicative of credential dumping
author: Satyam Kumar
date: 2026-11-15
logsource:
    category: process_access
    product: windows
detection:
    selection_lsass:
        TargetImage|endswith: '\lsass.exe'
    selection_access:
        GrantedAccess:
            - '0x1010'    # VM_READ | PROCESS_QUERY_LIMITED
            - '0x1fffff'  # PROCESS_ALL_ACCESS
            - '0x001f0fff' # Common Mimikatz
            - '0x000f0fff' # Common Mimikatz
    selection_known_tools:
        SourceImage|endswith:
            - '\mimikatz.exe'
            - '\procdump.exe'
            - '\sqldumper.exe'
            - '\werfault.exe'
            - '\comsvcs.dll'
            - '\rundll32.exe'
    selection_suspicious_path:
        SourceImage|contains:
            - '\Temp\'
            - '\AppData\'
            - '\Public\'
            - '\ProgramData\'
            - '\Downloads\'
        SourceImage|endswith: '.exe'
    condition: selection_lsass and (selection_access or selection_known_tools or selection_suspicious_path)
fields:
    - SourceImage
    - TargetImage
    - GrantedAccess
    - SourceProcessId
    - TargetProcessId
falsepositives:
    - Legitimate EDR/AV memory scanning (allowlist via SourceImage)
    - Debuggers (rare in production)
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
```

---

## 3. Test Results

| Test ID | Technique | Tool | Result |
|---------|-----------|------|--------|
| TEST-001 | T1003.001 | Atomic Red Team (Mimikatz) | ✅ ALERTED |
| TEST-002 | T1003.001 | Manual (comsvcs.dll MiniDump) | ✅ ALERTED |
| TEST-003 | T1003.001 | Manual (procdump) | ✅ ALERTED |

---

## 4. Tuning Notes

- **Critical**: Must allowlist legitimate EDR/AV processes via CDB
- GrantedAccess 0x1010 (VM_READ | PROCESS_QUERY_LIMITED) is most common for Mimikatz
- 0x1fffff = PROCESS_ALL_ACCESS (procdump default)

---

## 5. Interview Notes

> "This is the crown jewel detection. LSASS access with 0x1010 or 0x1fffff = credential theft in progress. Must have CDB allowlist for EDR/AV or you'll drown in FPs. Tested against Mimikatz, comsvcs.dll, procdump — all caught."