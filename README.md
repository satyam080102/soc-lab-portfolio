# SOC Analyst Portfolio — Hands-On Detection & Investigation

> **Satyam Kumar** | Security Analyst (1 yr 10 mo MSSP) | Targeting L1.5/L2 SOC / Detection Engineering
>
> **LinkedIn**: linkedin.com/in/satyam-kumar0801 | **Email**: mesatyamsharma2002@gmail.com

---

## 🎯 Summary

This repository documents a **30-day hands-on SOC lab project** completed while on bench between client projects. It demonstrates independent alert investigation, hypothesis-driven threat hunting, detection engineering across multiple platforms, and professional incident reporting — all mapped to MITRE ATT&CK.

**Core Achievement**: Built a local SOC environment (Wazuh + Sysmon + Suricata + Atomic Red Team), simulated 15+ attack techniques, authored 8 custom detection rules, conducted 4 threat hunts, and produced 3 professional investigation reports.

---

## 🏗️ Lab Architecture

![Lab Diagram](docs/images/lab-architecture.png)

| Component | Specification |
|-----------|---------------|
| **SIEM/XDR** | Wazuh 4.8 (Single-node: Indexer + Manager + Dashboard) |
| **Endpoint** | Windows 11 + Sysmon 15 (SwiftOnSecurity config) + Wazuh Agent |
| **Attacker** | Kali Linux + Atomic Red Team + Caldera |
| **Network IDS** | Suricata 7 + ET Open Ruleset + Custom Rules |
| **Network** | VirtualBox Host-Only (192.168.56.0/24) |
| **Host** | Windows 11, 32 GB RAM, 12 GB allocated to VMs |

📖 **[Full Setup Guide](docs/lab-quick-start.md)** — Reproducible in 2 hours.

---

## 📊 MITRE ATT&CK Coverage

| Tactic | Techniques Covered | Detections | Hunts | Investigations |
|--------|-------------------|------------|-------|----------------|
| Initial Access | 1 (T1566.001) | 0 | 0 | 1 |
| Execution | 3 (T1059.001, T1059.003, T1059.005) | 2 | 1 | 2 |
| Persistence | 2 (T1053.005, T1547.001) | 2 | 0 | 1 |
| Privilege Escalation | 1 (T1003.001) | 0 | 1 | 1 |
| Defense Evasion | 3 (T1070.004, T1218.011, T1562.001) | 2 | 1 | 2 |
| Credential Access | 2 (T1003.001, T1555.003) | 1 | 1 | 1 |
| Discovery | 2 (T1082, T1083) | 0 | 1 | 1 |
| Lateral Movement | 3 (T1021.002, T1021.004, T1021.006) | 1 | 1 | 1 |
| Collection | 1 (T1005) | 0 | 0 | 1 |
| Command & Control | 2 (T1071.001, T1071.004) | 1 | 1 | 1 |
| Exfiltration | 1 (T1041) | 0 | 1 | 1 |
| **TOTAL** | **21** | **9** | **8** | **12** |

📈 **[Full Coverage Tracker](docs/mitre-coverage-tracker.md)**

---

## 🔍 Investigations (3 Complete Reports)

| # | Scenario | Techniques | Classification | Report |
|---|----------|------------|----------------|--------|
| 01 | Brute Force → PowerShell Encoded Command → C2 Beacon | T1110.001, T1059.001, T1071.001 | **TRUE POSITIVE** | [`investigations/01/`](investigations/01-brute-force-powershell/report.md) |
| 02 | Threat Hunt: LOLBAS Execution + Credential Access | T1218.011, T1105, T1003.001 | **TRUE POSITIVE** (Hunt) | [`investigations/02/`](investigations/02-threat-hunt-lolbas-credaccess/report.md) |
| 03 | Capstone: Full Kill Chain (Phishing → Exfiltration) | 11 techniques, 7 tactics | **TRUE POSITIVE** | [`investigations/03/`](investigations/03-capstone-full-kill-chain/report.md) |

**Each report includes**: Executive summary, chronological timeline, evidence with SHA256 hashes, MITRE ATT&CK mapping, root cause analysis, containment actions, detection improvements.

---

## ⚙️ Detection Engineering (8 Rules, 4 Platforms)

| Rule ID | Name | Platforms | MITRE | FP Rate (Tuned) |
|---------|------|-----------|-------|-----------------|
| DET-001 | PowerShell Encoded Command + Network | Wazuh, Splunk, Suricata, Sigma | T1059.001, T1071.001 | 0.5/day |
| DET-002 | Suspicious CMD Arguments | Wazuh, Splunk, Sigma | T1059.003 | 0.2/day |
| DET-003 | Scheduled Task Persistence | Wazuh, Splunk, Sigma | T1053.005 | 0.1/day |
| DET-004 | Registry Run Keys Persistence | Wazuh, Splunk, Sigma | T1547.001 | 0.3/day |
| DET-005 | File Deletion (Anti-Forensics) | Wazuh, Splunk, Sigma | T1070.004 | 0.4/day |
| DET-006 | LOLBAS Rundll32 Proxy Execution | Wazuh, Splunk, Suricata, Sigma | T1218.011 | 0.2/day |
| DET-007 | LSASS Memory Access | Wazuh, Splunk, Sigma | T1003.001 | 0.1/day |
| DET-008 | SMB Lateral Movement | Wazuh, Splunk, Suricata, Sigma | T1021.002 | 0.3/day |

**Each rule folder includes**: Multi-platform syntax (Wazuh XML, Splunk SPL, Suricata, Sigma YAML), Atomic Red Team test results, false positive tuning log, MITRE tags.

📁 **[All Detections](detections/)**

---

## 🎯 Threat Hunts (4 Hypothesis-Driven)

| Hunt | Hypothesis | Techniques Hunted | Rules Created |
|------|------------|-------------------|---------------|
| 01 | Adversaries use LOLBAS for defense evasion | T1218.011, T1105, T1059.001 | DET-001, DET-006 |
| 02 | Credential dumping via LSASS access | T1003.001, T1555.003 | DET-007 |
| 03 | Lateral movement via SMB/WMI/WinRM | T1021.002, T1021.004, T1021.006 | DET-008 |
| 04 | C2 over HTTP/DNS with beaconing | T1071.001, T1071.004, T1041 | — |

**Methodology**: PEAK Framework (Prepare → Execute → Analyze → Knowledge). Each hunt: hypothesis doc, queries, findings, new rules, coverage map.

📁 **[All Hunts](hunts/)**

---

## 🛠️ Technical Skills Demonstrated

| Category | Tools & Proficiency |
|----------|---------------------|
| **SIEM** | Wazuh (WQL, Dashboards, Rules, CDB), Splunk (SPL, Data Models, Dashboards) |
| **Endpoint** | Sysmon (Event IDs 1,3,7,8,10,11,12,13,14,15,22,25), Wazuh Agent, Broadcom Symantec EDR (training) |
| **Network** | Suricata (Rules, Eve JSON), Wireshark (PCAP, TCP streams, JA3), Zeek (optional) |
| **Attack Simulation** | Atomic Red Team (Invoke-AtomicTest), Caldera (Adversary Profiles) |
| **Frameworks** | MITRE ATT&CK (Mapping, Coverage, Gap Analysis), Cyber Kill Chain, NIST IR |
| **Scripting** | Python (Basic - log parsing, API), PowerShell (Investigation, Automation), SQL (Basic) |
| **IR/Forensics** | Memory acquisition (WinPMEM), Disk imaging (FTK Imager), Evidence hashing, Chain of custody |
| **Ticketing** | Jira (SLA tracking, escalation packages) |

---

## 📈 Professional Experience (Context)

**Security Analyst L1** | Aguna Solutions (MSSP) | Jan 2025 – Present
- 24/7 SOC monitoring for banking/enterprise clients via ZeroHack SIEM
- **12% reduction in false-positive escalations** via improved classification & quality reviews
- **12-minute average Tier-2 escalation** SLA via complete investigation packages
- UEBA alert investigation, MITRE ATT&CK mapping, Broadcom Symantec EDR exposure

**Independent Labs** (2024-2025)
- Detection Engineering Lab: Wazuh + Suricata (brute force, PowerShell, privilege escalation, log tampering)
- Detection Engineering Lab: Splunk + Suricata (multi-source correlation, SPL dashboards)

**Certifications**
- Ethical Hacking & Countermeasures, Endpoint Security, AWS Security, Networking (Craw Security, 2025)
- Broadcom Symantec EDR & Email Security (2025)
- M.Sc. Computer Science (CCS University, 2025)

---

## 🚀 Next Steps

Actively seeking **SOC L1.5/L2 Analyst**, **Detection Engineer**, or **Threat Hunter** roles. Available for immediate start.

**Portfolio Walkthrough**: Happy to schedule a 30-min screen share to walk through the capstone investigation and detection rules.

---

*Last updated: 2026-11-11 | This portfolio is actively maintained.*