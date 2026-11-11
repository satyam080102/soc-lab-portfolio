# Detection Rule: Scheduled Task Persistence

## 📋 Rule Metadata

| Field | Value |
|-------|-------|
| **Rule ID** | DET-003 |
| **Rule Name** | Scheduled Task Creation Persistence |
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
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task |

### Threat Scenario
Adversaries create scheduled tasks to execute payloads at system startup, user logon, or recurring intervals. Common tools: `schtasks.exe`, `TaskService` COM, PowerShell `ScheduledTask` cmdlets.

---

## 2. Rule Logic

### Wazuh Rule
```xml
<!-- File: rule.wazuh.xml -->
<group name="persistence,scheduled_task">
  <rule id="100004" level="10">
    <if_sid>92720</if_sid>  <!-- Base task creation rule -->
    <field name="win.eventdata.image">.*\\schtasks\.exe</field>
    <field name="win.eventdata.commandLine">(/create|/tn\s+|/tr\s+|/sc\s+(onlogon|onstart|onidle))</field>
    <description>Scheduled task created via schtasks.exe (T1053.005)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

  <rule id="100005" level="12">
    <if_sid>92720</if_sid>
    <field name="win.eventdata.commandLine">(powershell|cmd|wscript|cscript|mshta).*(-enc|-encodedcommand|iex|downloadstring)</field>
    <description>Scheduled task with encoded/powershell command (T1053.005, T1059.001)</description>
    <mitre>
      <id>T1053.005</id>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <rule id="100006" level="9" frequency="2" timeframe="300">
    <if_sid>100004</if_sid>
    <same_field name="data.win.eventdata.targetUserName"/>
    <description>Multiple scheduled tasks created by same user (T1053.005)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>
</group>
```

### Splunk SPL
```spl
# File: rule.spl
index=winevents sourcetype=xmlwineventlog EventCode=4698
| where match(Task_Content, "powershell|cmd|wscript|cscript|mshta")
| where match(Task_Content, "(-enc|-encodedcommand|iex|downloadstring|invoke-expression)")
| eval severity="HIGH", mitre="T1053.005,T1059.001"
| table _time, host, SubjectUserName, TaskName, Task_Content, severity, mitre
```

### Sigma Rule
```yaml
# File: rule.sigma.yml
title: Scheduled Task Persistence with Suspicious Command
id: b3c4d5e6-f789-0123-cdef-345678901234
status: test
description: Detects scheduled task creation with PowerShell/cmd encoded commands
author: Satyam Kumar
date: 2026-11-18
logsource:
    category: scheduled_task_creation
    product: windows
detection:
    selection_task:
        EventID: 4698
    selection_suspicious:
        TaskContent|contains:
            - 'powershell'
            - 'cmd'
            - 'wscript'
            - 'cscript'
            - 'mshta'
    selection_encoded:
        TaskContent|contains:
            - '-enc'
            - '-encodedcommand'
            - 'iex'
            - 'invoke-expression'
            - 'downloadstring'
    condition: selection_task and selection_suspicious and selection_encoded
fields:
    - TaskName
    - TaskContent
    - SubjectUserName
falsepositives:
    - Legitimate admin task creation (rare with encoded commands)
level: high
tags:
    - attack.persistence
    - attack.t1053.005
```

---

## 3. Test Results

| Test ID | Technique | Tool | Result |
|---------|-----------|------|--------|
| TEST-001 | T1053.005 | Atomic Red Team | ✅ ALERTED |
| TEST-002 | T1053.005 | Manual (schtasks + encoded PS) | ✅ ALERTED |

---

## 4. Interview Notes

> "Catches the classic 'schtasks /create /tr powershell -enc' pattern. Frequency rule catches multiple tasks by same user — common in persistence."