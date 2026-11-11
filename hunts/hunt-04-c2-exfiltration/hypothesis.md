# Hunt Hypothesis: C2 & Exfiltration (HTTP, DNS, Beaconing)

## Hunt ID: HUNT-004
**Date**: 2026-11-20
**Analyst**: Satyam Kumar
**Framework**: PEAK (Prepare → Execute → Analyze → Knowledge)

---

## 1. Prepare: Hypothesis Definition

**Hypothesis**: *Adversaries with established access will use HTTP/S (T1071.001) or DNS (T1071.004) for command & control, with regular beaconing patterns, and exfiltrate data over the same channel (T1041).*

**Why This Matters**:
- C2 is the lifeline of persistent access
- Beaconing patterns (interval, jitter, size) are detectable
- Exfiltration often uses existing C2 channel (blending)
- DNS tunneling evades HTTP inspection

**Expected TTPs**:
| Technique | Description |
|-----------|-------------|
| T1071.001 | Web Protocols (HTTP/S C2) |
| T1071.004 | DNS (DNS tunneling, DGAs) |
| T1573.001 | Encrypted Channel (TLS, custom crypto) |
| T1041 | Exfiltration Over C2 Channel |
| T1567 | Exfiltration Over Web Service (cloud storage) |

---

## 2. Prepare: Data Sources

| Source | Events | Key Fields |
|--------|--------|------------|
| Suricata Eve | http, dns, tls | http_user_agent, http_method, dns_query, tls_ja3, destination.ip |
| Sysmon | 3 (Network), 22 (DNS) | SourceImage, DestinationIp, DestinationPort, QueryName |
| Zeek (optional) | conn, http, dns, ssl | duration, orig_bytes, resp_bytes, cert_subject |

---

## 3. Execute: Queries Run

### Query 1: Regular Beaconing (HTTP GET/POST at fixed intervals)
```sql
-- Suricata HTTP events, group by source/dest, check interval variance
event_type:http AND destination.ip:203.0.113.45
| stats count avg(interval) stdev(interval) by source.ip, destination.ip, http.http_method
| where stdev(interval) < 10 AND count > 5
```

**Result**: 1 hit — win-endpoint → 203.0.113.45, GET /beacon, interval=60s ±2s, count=180

### Query 2: High Entropy Domains (DGA / DNS Tunneling)
```sql
event_type:dns AND dns.type:query
| eval entropy=ut_shannon(dns.query)
| where entropy > 3.5 AND length(dns.query) > 30
| stats count by dns.query, source.ip, entropy
```

**Result**: 0 hits (no DNS tunneling in this simulation)

### Query 3: Large HTTP POST (Exfiltration)
```sql
event_type:http AND http.http_method:POST
| eval size=http.request_body_len + http.response_body_len
| where size > 100000
| stats sum(size) as total_bytes by source.ip, destination.ip, http.url
```

**Result**: 1 hit — win-endpoint → 203.0.113.45, POST /exfil, 12.4 MB (exfil.tar.gz)

### Query 4: JA3 Fingerprinting (TLS Client Identification)
```sql
event_type:tls AND tls.ja3:*
| stats count by tls.ja3, source.ip, destination.ip
| where count > 10
```

**Result**: 
- JA3: `a0e9f5d64349fb13191bc781f81f42e4` (PowerShell default) — 180 connections
- JA3: `72a589da586844d7f0818ce684948eea` (curl) — 12 connections

### Query 5: Long-Lived Connections
```sql
event_type:http
| stats max(@timestamp) as last, min(@timestamp) as first by source.ip, destination.ip, http.http_method
| eval duration=last-first
| where duration > 3600
```

**Result**: win-endpoint → 203.0.113.45, duration=10800s (3 hours)

---

## 4. Analyze: Findings

| Finding | Details | MITRE | Confidence |
|---------|---------|-------|------------|
| HTTP Beaconing | GET /beacon every 60s ±2s for 3 hours | T1071.001 | HIGH |
| HTTP Exfiltration | POST /exfil 12.4 MB compressed archive | T1041 | HIGH |
| TLS JA3 Consistency | Single JA3 (PowerShell) for all beacon traffic | T1573.001 | HIGH |
| DNS Tunneling | Not observed | T1071.004 | NOT FOUND |

---

## 5. Knowledge: Detection Improvements

| Rule | Enhancement |
|------|-------------|
| DET-001 | Added Suricata HTTP beacon detection (interval + size) |
| DET-001 | Added Suricata large POST detection (exfil) |
| New | JA3 fingerprint allowlist/blocklist for known tools |

---

## 6. MITRE Coverage Update

| Technique | Previous | New | Evidence |
|-----------|----------|-----|----------|
| T1071.001 | Level 2 | Level 3 | HUNT-004 + DET-001 Suricata |
| T1041 | Level 0 | Level 2 | HUNT-004 (exfil detected) |
| T1071.004 | Level 0 | Level 1 (hunted) | HUNT-004 (no finding) |
| T1573.001 | Level 0 | Level 1 | HUNT-004 (JA3 consistency) |

---

**Hunt Status**: ✅ COMPLETE
**Analyst**: Satyam Kumar
**Date**: 2026-11-20