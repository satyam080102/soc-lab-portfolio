#!/bin/bash
# Wazuh/OpenSearch Query Helpers
# Usage: source this file, then use functions

# Base URL for Wazuh Indexer
WAZUH_URL="https://192.168.56.10:9200"
AUTH="admin:admin"  # Change in production

# Common index patterns
ALERTS_INDEX="wazuh-alerts-*"
MONITORING_INDEX="wazuh-monitoring-*"

# Function: Search alerts
wazuh_search() {
    local query="$1"
    local index="${2:-$ALERTS_INDEX}"
    curl -k -u "$AUTH" -X POST "$WAZUH_URL/$index/_search" \
        -H "Content-Type: application/json" \
        -d "$query" | jq .
}

# Function: Brute force failures
wazuh_bruteforce() {
    local ip="${1:-}"
    local user="${2:-}"
    local time_range="${3:-now-1h}"

    local query=$(cat <<EOF
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "rule.id": "5710" }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ]
      $( [ -n "$ip" ] && echo ", \"filter\": [{ \"term\": { \"source.ip\": \"$ip\" }}]" )"
      $( [ -n "$user" ] && echo ", \"filter\": [{ \"term\": { \"data.win.eventdata.targetUserName\": \"$user\" }}]" )"
    }
  },
  "sort": [{ "@timestamp": { "order": "asc" }}]
}
EOF
)
    wazuh_search "$query"
}

# Function: Successful logons after failures
wazuh_success_after_fail() {
    local user="${1:-}"
    local time_range="${2:-now-1h}"

    local query=$(cat <<EOF
{
  "size": 50,
  "query": {
    "bool": {
      "must": [
        { "term": { "rule.id": "5715" }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ]
      $( [ -n "$user" ] && echo ", \"filter\": [{ \"term\": { \"data.win.eventdata.targetUserName\": \"$user\" }}]" )"
    }
  }
}
EOF
)
    wazuh_search "$query"
}

# Function: Process creation by user
wazuh_process_by_user() {
    local user="${1:-}"
    local time_range="${2:-now-1h}"

    local query=$(cat <<EOF
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "rule.id": "92710" }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ]
      $( [ -n "$user" ] && echo ", \"filter\": [{ \"term\": { \"data.win.eventdata.targetUserName\": \"$user\" }}]" )"
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.parentImage", "data.win.eventdata.processId"]
}
EOF
)
    wazuh_search "$query"
}

# Function: Network connections from PID
wazuh_network_from_pid() {
    local pid="${1:-}"
    local time_range="${2:-now-1h}"

    local query=$(cat <<EOF
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "data.win.eventdata.sourceProcessId": "$pid" }},
        { "term": { "data.win.eventdata.eventType": "3" }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ]
    }
  },
  "_source": ["@timestamp", "data.win.eventdata.destinationIp", "data.win.eventdata.destinationPort", "data.win.eventdata.protocol"]
}
EOF
)
    wazuh_search "$query"
}

# Function: Suricata alerts
wazuh_suricata_alerts() {
    local sig_id="${1:-}"
    local time_range="${2:-now-1h}"

    local query=$(cat <<EOF
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "event_type": "alert" }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ]
      $( [ -n "$sig_id" ] && echo ", \"filter\": [{ \"term\": { \"suricata.signature_id\": \"$sig_id\" }}]" )"
    }
  }
}
EOF
)
    wazuh_search "$query"
}

# Function: LSASS access
wazuh_lsass_access() {
    local time_range="${1:-now-24h}"

    local query=$(cat <<EOF
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "data.win.eventdata.targetImage": "lsass.exe" }},
        { "terms": { "data.win.eventdata.grantedAccess": ["0x1010", "0x1fffff", "0x001f0fff", "0x000f0fff"] }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ]
    }
  }
}
EOF
)
    wazuh_search "$query"
}

# Function: Scheduled task creation
wazuh_scheduled_tasks() {
    local time_range="${1:-now-24h}"

    local query=$(cat <<EOF
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "rule.id": "92720" }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ]
    }
  }
}
EOF
)
    wazuh_search "$query"
}

# Function: Registry Run keys
wazuh_registry_run() {
    local time_range="${1:-now-24h}"

    local query=$(cat <<EOF
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "wildcard": { "data.win.eventdata.targetObject": "*\\Run" }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ]
    }
  }
}
EOF
)
    wazuh_search "$query"
}

# Function: PowerShell encoded commands
wazuh_ps_encoded() {
    local time_range="${1:-now-24h}"

    local query=$(cat <<EOF
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "rule.id": "92710" }},
        { "regexp": { "data.win.eventdata.commandLine": "(?i)(-enc|-encodedcommand|frombase64string|iex|invoke-expression)" }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ]
    }
  }
}
EOF
)
    wazuh_search "$query"
}

# Function: LOLBAS from suspicious paths
wazuh_lolbas_suspicious() {
    local time_range="${1:-now-24h}"

    local query=$(cat <<EOF
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "terms": { "data.win.eventdata.image": ["certutil.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "wmic.exe", "reg.exe"] }},
        { "range": { "@timestamp": { "gte": "$time_range" }}}
      ],
      "must_not": [
        { "wildcard": { "data.win.eventdata.image": "C:\\Windows\\System32\\*" }},
        { "wildcard": { "data.win.eventdata.image": "C:\\Windows\\SysWOW64\\*" }}
      ]
    }
  }
}
EOF
)
    wazuh_search "$query"
}

echo "Wazuh query helpers loaded. Functions available:"
echo "  wazuh_bruteforce [ip] [user] [time_range]"
echo "  wazuh_success_after_fail [user] [time_range]"
echo "  wazuh_process_by_user [user] [time_range]"
echo "  wazuh_network_from_pid [pid] [time_range]"
echo "  wazuh_suricata_alerts [signature_id] [time_range]"
echo "  wazuh_lsass_access [time_range]"
echo "  wazuh_scheduled_tasks [time_range]"
echo "  wazuh_registry_run [time_range]"
echo "  wazuh_ps_encoded [time_range]"
echo "  wazuh_lolbas_suspicious [time_range]"