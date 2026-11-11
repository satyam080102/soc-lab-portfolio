# Detection Rule: LOLBAS Rundll32 Proxy Execution

## 📋 Rule Metadata

| Field | Value |
|-------|-------|
| **Rule ID** | DET-006 |
| **Rule Name** | LOLBAS Rundll32 Proxy Execution |
| **Author** | Satyam Kumar |
| **Date Created** | 2026-11-15 |
| **Last Updated** | 2026-11-25 |
| **Status** | PRODUCTION |
| **Platform** | Wazuh, Splunk, Suricata, Sigma |
| **Severity** | HIGH |

---

## 1. Threat Context

### MITRE ATT&CK Mapping
| Tactic | Technique ID | Technique Name |
|--------|--------------|----------------|
| Defense Evasion | T1218.011 | Signed Binary Proxy Execution: Rundll32 |

### Threat Scenario
Adversaries use `rundll32.exe` (signed Microsoft binary) to execute arbitrary code via DLL exports, commonly `comsvcs.dll MiniDump` for LSASS memory dumping, or custom DLLs for payload execution.

---

## 2. Rule Logic

### Wazuh Rule
```xml
<!-- File: rule.wazuh.xml -->
<group name="lolbas,rundll32,defense_evasion">
  <rule id="100011" level="12">
    <if_sid>92750</if_sid>
    <field name="win.eventdata.image">.*\\rundll32\.exe</field>
    <field name="win.eventdata.commandLine">(comsvcs\.dll|MiniDump|#1|EntryPoint|DllRegisterServer|DllUnregisterServer)</field>
    <description>Rundll32 executing suspicious DLL exports (T1218.011)</description>
    <mitre>
      <id>T1218.011</id>
    </mitre>
  </rule>

  <rule id="100012" level="10">
    <if_sid>92750</if_sid>
    <field name="win.eventdata.image">.*\\rundll32\.exe</field>
    <field name="win.eventdata.commandLine">.*\\(Temp|AppData|Public|ProgramData|Downloads)\\.*\.dll</field>
    <description>Rundll32 loading DLL from suspicious path (T1218.011)</description>
    <mitre>
      <id>T1218.011</id>
    </mitre>
  </rule>

  <rule id="100013" level="11" frequency="2" timeframe="60">
    <if_sid>100011</if_sid>
    <same_field name="data.win.eventdata.targetUserName"/>
    <description>Multiple rundll32 suspicious executions by same user (T1218.011)</description>
    <mitre>
      <id>T1218.011</id>
    </mitre>
  </rule>
</group>
```

### Splunk SPL
```spl
# File: rule.spl
index=winevents sourcetype=xmlwineventlog EventCode=4688
| where like(New_Process_Name, "%rundll32.exe")
| where match(Command_Line, "(comsvcs\.dll|MiniDump|#1|EntryPoint|DllRegisterServer|DllUnregisterServer)")
| OR where match(Command_Line, ".*\\(Temp|AppData|Public|ProgramData|Downloads)\\.*\.dll")
| eval severity="HIGH", mitre="T1218.011"
| table _time, host, New_Process_Name, Command_Line, ParentProcessName, severity, mitre
```

### Suricata Rule
```suricata
# File: rule.suricata
alert http any any -> any any (
    msg:"SOC-DET-006 Rundll32 LOLBAS Activity";
    flow:established,to_server;
    content:"rundll32"; http_user_agent;
    pcre:"/(comsvcs\.dll|MiniDump|EntryPoint)/i";
    metadata:mitre_technique T1218.011;
    classtype:trojan-activity;
    sid:1000006;
    rev:1;
)
```

### Sigma Rule
```yaml
# File: rule.sigma.yml
title: LOLBAS Rundll32 Proxy Execution
id: e6f78901-2345-6789-fghi-678901234567
status: test
description: Detects rundll32.exe executing suspicious DLL exports or loading from suspicious paths
author: Satyam Kumar
date: 2026-11-15
logsource:
    category: process_creation
    product: windows
detection:
    selection_rundll32:
        Image|endswith: '\rundll32.exe'
    selection_comsvcs:
        CommandLine|contains:
            - 'comsvcs.dll'
            - 'MiniDump'
            - '#1'
            - 'EntryPoint'
    selection_suspicious_path:
        CommandLine|contains:
            - '\Temp\'
            - '\AppData\'
            - '\Public\'
            - '\ProgramData\'
            - '\Downloads\'
        CommandLine|endswith: '.dll'
    condition: selection_rundll32 and (selection_comsvcs or selection_suspicious_path)
fields:
    - CommandLine
    - ParentImage
    - CurrentDirectory
falsepositives:
    - Legitimate software using rundll32 (rare with comsvcs.dll MiniDump)
level: high
tags:
    - attack.defense_evasion
    - attack.t1218.011
```

---

## 3. Test Results

| Test ID | Technique | Tool | Result |
|---------|-----------|------|--------|
| TEST-001 | T1218.011 | Atomic Red Team | ✅ ALERTED |
| TEST-002 | T1218.011 | Manual (comsvcs.dll MiniDump) | ✅ ALERTED |

---

## 4. Interview Notes

> "Rundll32 + comsvcs.dll MiniDump is the classic LSASS dump technique. Catching it at process creation (not just memory access) gives earlier detection. Suricata UA rule catches C2 using rundll32 as HTTP client."