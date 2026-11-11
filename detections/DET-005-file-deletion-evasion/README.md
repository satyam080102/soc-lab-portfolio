# Detection Rule: File Deletion (Anti-Forensics)

## 📋 Rule Metadata

| Field | Value |
|-------|-------|
| **Rule ID** | DET-005 |
| **Rule Name** | File Deletion via Anti-Forensics Tools |
| **Author** | Satyam Kumar |
| **Date Created** | 2026-11-19 |
| **Last Updated** | 2026-11-25 |
| **Status** | PRODUCTION |
| **Platform** | Wazuh, Splunk, Sigma |
| **Severity** | HIGH |

---

## 1. Threat Context

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion |

### Threat Scenario
Adversaries use tools like `cipher.exe /w`, `sdelete.exe`, `del /f /s /q`, PowerShell `Remove-Item -Force -Recurse` to delete files and wipe free space to hinder forensics.

---

## 2. Rule Logic

### Wazuh Rule
```xml
<!-- File: rule.wazuh.xml -->
<group name="defense_evasion,file_deletion">
  <rule id="100009" level="10">
    <if_sid>92740</if_sid>
    <field name="win.eventdata.image">.*\\(cipher|sdelete|shred)\.exe</field>
    <field name="win.eventdata.commandLine">(\/w|/w:|/p|/s|/q)</field>
    <description>Anti-forensics file deletion tool executed (T1070.004)</description>
    <mitre>
      <id>T1070.004</id>
    </mitre>
  </rule>

  <rule id="100010" level="9">
    <if_sid>92740</if_sid>
    <field name="win.eventdata.image">.*\\powershell\.exe</field>
    <field name="win.eventdata.commandLine">(Remove-Item|del|erase).*(-Force|-Recurse|-f|-s|-q|-r)</field>
    <description>PowerShell/cmd mass file deletion (T1070.004)</description>
    <mitre>
      <id>T1070.004</id>
    </mitre>
  </rule>
</group>
```

### Splunk SPL
```spl
# File: rule.spl
index=winevents sourcetype=xmlwineventlog EventCode=4688
| where match(New_Process_Name, "(cipher|sdelete|shred)\.exe")
| OR where (match(New_Process_Name, "powershell\.exe") AND match(Command_Line, "(Remove-Item|del|erase).*(-Force|-Recurse|-f|-s|-q|-r)"))
| eval severity="HIGH", mitre="T1070.004"
| table _time, host, New_Process_Name, Command_Line, ParentProcessName, severity, mitre
```

### Sigma Rule
```yaml
# File: rule.sigma.yml
title: Anti-Forensics File Deletion
id: d5e6f789-0123-4567-efgh-567890123456
status: test
description: Detects execution of file deletion/wiping tools
author: Satyam Kumar
date: 2026-11-19
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\cipher.exe'
            - '\sdelete.exe'
            - '\shred.exe'
    selection_ps:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Remove-Item'
            - 'del '
            - 'erase '
    selection_flags:
        CommandLine|contains:
            - '-Force'
            - '-Recurse'
            - '-f'
            - '-s'
            - '-q'
            - '-r'
            - '/w'
            - '/p'
    condition: selection_tools or (selection_ps and selection_flags)
fields:
    - Image
    - CommandLine
    - ParentImage
falsepositives:
    - Legitimate admin cleanup scripts
    - Disk cleanup utilities
level: high
tags:
    - attack.defense_evasion
    - attack.t1070.004
```

---

## 3. Test Results

| Test ID | Technique | Tool | Result |
|---------|-----------|------|--------|
| TEST-001 | T1070.004 | Atomic Red Team | ✅ ALERTED |
| TEST-002 | T1070.004 | Manual (cipher /w) | ✅ ALERTED |

---

## 4. Interview Notes

> "Catches both dedicated wipers (cipher, sdelete) and PowerShell mass deletion. Key differentiator: flags like /w (wipe free space), -Force -Recurse combo."