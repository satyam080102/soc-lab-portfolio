# Detection Rule: Suspicious CMD Arguments

## 📋 Rule Metadata

| Field | Value |
|-------|-------|
| **Rule ID** | DET-002 |
| **Rule Name** | Suspicious Command Line Arguments (cmd.exe) |
| **Author** | Satyam Kumar |
| **Date Created** | 2026-11-13 |
| **Last Updated** | 2026-11-25 |
| **Status** | PRODUCTION |
| **Platform** | Wazuh, Splunk, Sigma |
| **Severity** | MEDIUM |

---

## 1. Threat Context

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |

### Threat Scenario
Adversaries use `cmd.exe` with suspicious arguments to execute payloads, bypass logging, or chain commands: `/c`, `/k`, `/v:on`, `&&`, `||`, `|`, `>`, `<`, `^`, `cmd /c "..."`, nested cmd.

---

## 2. Rule Logic

### Wazuh Rule
```xml
<!-- File: rule.wazuh.xml -->
<group name="cmd,suspicious_args">
  <rule id="100002" level="8">
    <if_sid>92700</if_sid>  <!-- Base cmd.exe rule -->
    <field name="win.eventdata.image">.*\\cmd\.exe</field>
    <field name="win.eventdata.commandLine">(\/c|\/k|\/v:on|&&|\|\||>|<|\^|cmd\.exe\s+\/c)</field>
    <description>Suspicious cmd.exe command line arguments (T1059.003)</description>
    <mitre>
      <id>T1059.003</id>
    </mitre>
  </rule>

  <rule id="100003" level="10" frequency="3" timeframe="60">
    <if_sid>100002</if_sid>
    <same_field name="data.win.eventdata.processId"/>
    <description>Multiple suspicious cmd.exe executions from same process (T1059.003)</description>
    <mitre>
      <id>T1059.003</id>
    </mitre>
  </rule>
</group>
```

### Splunk SPL
```spl
# File: rule.spl
index=winevents sourcetype=xmlwineventlog EventCode=4688
| where like(New_Process_Name, "%cmd.exe")
| where match(Command_Line, "(/c|/k|/v:on|&&|\|\||>|<|\^|cmd\.exe\s+/c)")
| eval suspicious_args=case(
    match(Command_Line, "cmd\.exe\s+/c"), "nested_cmd",
    match(Command_Line, "/v:on"), "delayed_expansion",
    match(Command_Line, "&&|\|\|"), "command_chaining",
    match(Command_Line, ">|<"), "redirection",
    1=1, "other"
)
| stats count min(_time) as first_time max(_time) as last_time by host, New_Process_Name, Command_Line, ParentProcessName, suspicious_args
| where count >= 2
| eval severity="MEDIUM", mitre="T1059.003"
```

### Sigma Rule
```yaml
# File: rule.sigma.yml
title: Suspicious CMD Arguments
id: a2b3c4d5-e6f7-8901-bcde-f23456789012
status: test
description: Detects suspicious cmd.exe command line arguments used for obfuscation and command chaining
author: Satyam Kumar
date: 2026-11-13
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\cmd.exe'
    selection_args:
        CommandLine|contains:
            - '/c'
            - '/k'
            - '/v:on'
            - '&&'
            - '||'
            - '>'
            - '<'
            - '^'
    condition: selection_cmd and selection_args
fields:
    - CommandLine
    - ParentImage
    - CurrentDirectory
falsepositives:
    - Legitimate batch scripts
    - Software installers
level: medium
tags:
    - attack.execution
    - attack.t1059.003
```

---

## 3. Test Results

| Test ID | Technique | Tool | Result |
|---------|-----------|------|--------|
| TEST-001 | T1059.003 | Atomic Red Team | ✅ ALERTED |
| TEST-002 | T1059.003 | Manual (nested cmd) | ✅ ALERTED |

---

## 4. Tuning Notes

- High FP from legitimate batch scripts → frequency threshold (3 in 60s)
- Exclude known good parent processes (SCCM, backup agents) via CDB

---

## 5. Interview Notes

> "Simple but effective — catches command chaining and obfuscation that PowerShell rules miss. Tuned with frequency threshold to reduce batch script noise."