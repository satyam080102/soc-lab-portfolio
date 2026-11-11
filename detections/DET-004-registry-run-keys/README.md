# Detection Rule: Registry Run Keys Persistence

## 📋 Rule Metadata

| Field | Value |
|-------|-------|
| **Rule ID** | DET-004 |
| **Rule Name** | Registry Run Key Persistence |
| **Author** | Satyam Kumar |
| **Date Created** | 2026-11-18 |
| **Last Updated** | 2026-11-25 |
| **Status** | PRODUCTION |
| **Platform** | Wazuh, Splunk, Sigma |
| **Severity** | HIGH |

---

## 1. Threat Context

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |

### Threat Scenario
Adversaries add entries to Registry Run keys (HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run, RunOnce) to execute payloads at user logon or system boot.

---

## 2. Rule Logic

### Wazuh Rule
```xml
<!-- File: rule.wazuh.xml -->
<group name="persistence,registry_run">
  <rule id="100007" level="10">
    <if_sid>92730</if_sid>  <!-- Base registry rule -->
    <field name="win.eventdata.targetObject">.*\\Run$</field>
    <field name="win.eventdata.details">(powershell|cmd|wscript|cscript|mshta|rundll32).*(-enc|-encodedcommand|iex|downloadstring)</field>
    <description>Registry Run key modified with suspicious command (T1547.001)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <rule id="100008" level="9">
    <if_sid>92730</if_sid>
    <field name="win.eventdata.targetObject">.*\\(Run|RunOnce)$</field>
    <field name="win.eventdata.details">.*\\(Temp|AppData|Public|ProgramData)\\.*\.(ps1|bat|cmd|exe|dll|vbs|js)</field>
    <description>Registry Run key pointing to script in suspicious location (T1547.001)</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>
</group>
```

### Splunk SPL
```spl
# File: rule.spl
index=winevents sourcetype=xmlwineventlog EventCode IN (12,13,14)
| where match(TargetObject, ".*\\(Run|RunOnce)$")
| where match(Details, "(powershell|cmd|wscript|cscript|mshta|rundll32).*(-enc|-encodedcommand|iex|downloadstring)")
| eval severity="HIGH", mitre="T1547.001"
| table _time, host, TargetObject, Details, ProcessName, severity, mitre
```

### Sigma Rule
```yaml
# File: rule.sigma.yml
title: Registry Run Key Persistence with Suspicious Command
id: c4d5e6f7-8901-2345-defg-456789012345
status: test
description: Detects Registry Run/RunOnce keys modified with suspicious commands
author: Satyam Kumar
date: 2026-11-18
logsource:
    category: registry_event
    product: windows
detection:
    selection_reg:
        EventID: 13  # Registry value set
        TargetObject|endswith: '\Run'
    selection_suspicious:
        Details|contains:
            - 'powershell'
            - 'cmd'
            - 'wscript'
            - 'cscript'
            - 'mshta'
            - 'rundll32'
    selection_encoded:
        Details|contains:
            - '-enc'
            - '-encodedcommand'
            - 'iex'
            - 'invoke-expression'
            - 'downloadstring'
    condition: selection_reg and selection_suspicious and selection_encoded
fields:
    - TargetObject
    - Details
    - ProcessName
falsepositives:
    - Legitimate software installation (allowlist known installers)
level: high
tags:
    - attack.persistence
    - attack.t1547.001
```

---

## 3. Test Results

| Test ID | Technique | Tool | Result |
|---------|-----------|------|--------|
| TEST-001 | T1547.001 | Atomic Red Team | ✅ ALERTED |
| TEST-002 | T1547.001 | Manual (reg add HKCU\Run) | ✅ ALERTED |

---

## 4. Interview Notes

> "Run key monitoring is baseline hygiene. The value is combining location (Run/RunOnce) + command type (PowerShell/cmd) + encoding + suspicious path (Temp/AppData). Three-layer filter = low FP."