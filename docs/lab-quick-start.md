# Lab Quick-Start Guide: Wazuh + Windows + Kali
**One-time setup — follow once, then reference for rebuilds**

---

## 1. Prerequisites (Host: Windows 11, 32 GB RAM)

| Software | Download Link |
|----------|---------------|
| VirtualBox 7.0+ | https://www.virtualbox.org/wiki/Downloads |
| VirtualBox Extension Pack | Same page (for USB 3.0, PXE boot) |
| Ubuntu 22.04 Server ISO | https://ubuntu.com/download/server |
| Windows 10/11 Enterprise Eval ISO | https://www.microsoft.com/en-us/evalcenter/ |
| Kali Linux ISO | https://www.kali.org/get-kali/ |

---

## 2. VirtualBox Network Setup

### Create Host-Only Network
```
File → Host Network Manager → Create
Name: vboxnet0
IPv4: 192.168.56.1/24
DHCP: DISABLED (we use static IPs)
```

### VM Network Adapter Settings (All 3 VMs)
- Adapter 1: **Host-Only Adapter** → `vboxnet0`
- Adapter 2: **NAT** (for internet updates — optional, can enable temporarily)

---

## 3. VM Creation Specs

### Wazuh Manager (Ubuntu 22.04)
```
Name: wazuh-manager
Type: Linux → Ubuntu (64-bit)
RAM: 4096 MB (4 GB)
CPU: 2 vCPU
Disk: 60 GB (VDI, dynamically allocated)
Network: Adapter 1 → Host-Only (vboxnet0)
```

### Windows 10/11 Endpoint
```
Name: win-endpoint
Type: Microsoft Windows → Windows 10/11 (64-bit)
RAM: 4096 MB (4 GB)
CPU: 2 vCPU
Disk: 80 GB (VDI, dynamically allocated)
Network: Adapter 1 → Host-Only (vboxnet0)
```

### Kali Linux Attacker
```
Name: kali-attacker
Type: Linux → Debian (64-bit)  [Kali is Debian-based]
RAM: 4096 MB (4 GB)
CPU: 2 vCPU
Disk: 40 GB (VDI, dynamically allocated)
Network: Adapter 1 → Host-Only (vboxnet0)
```

---

## 4. Static IP Configuration

### Ubuntu (Wazuh) — Netplan
```bash
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    enp0s3:  # check with `ip a`
      addresses: [192.168.56.10/24]
      routes:
        - to: default
          via: 192.168.56.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```
```bash
sudo netplan apply
```

### Windows — PowerShell (Admin)
```powershell
# Check interface alias
Get-NetIPConfiguration

# Set static IP (adjust InterfaceAlias)
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.20 -PrefixLength 24 -DefaultGateway 192.168.56.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8,1.1.1.1
```

### Kali — NetworkManager
```bash
nmcli con mod "Wired connection 1" ipv4.method manual ipv4.addresses 192.168.56.30/24 ipv4.gateway 192.168.56.1 ipv4.dns "8.8.8.8,1.1.1.1"
nmcli con up "Wired connection 1"
```

### Verify Connectivity
```bash
# From each VM:
ping 192.168.56.10  # Wazuh
ping 192.168.56.20  # Windows
ping 192.168.56.30  # Kali
```

---

## 5. Wazuh Single-Node Install (on Ubuntu VM)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y curl gnupg2 apt-transport-https

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update

# Install single-node (indexer + manager + dashboard)
sudo apt install -y wazuh-manager wazuh-indexer wazuh-dashboard filebeat

# Start services
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

### Access Dashboard
- URL: `https://192.168.56.10` (accept self-signed cert)
- Default user: `admin` / password: shown in install output or run:
```bash
sudo /usr/share/wazuh-indexer/bin/wazuh-indexer-passwords.sh
```

---

## 6. Windows Endpoint: Sysmon + Wazuh Agent

### Install Sysmon (PowerShell Admin)
```powershell
# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig.xml" -OutFile "C:\Windows\sysmonconfig.xml"

# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Temp\Sysmon.zip"
Expand-Archive -Path "C:\Temp\Sysmon.zip" -DestinationPath "C:\Temp\Sysmon" -Force

# Install with config
C:\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\sysmonconfig.xml
```

### Install Wazuh Agent
```powershell
# Download MSI
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi" -OutFile "C:\Temp\wazuh-agent.msi"

# Install (replace MANAGER_IP)
msiexec /i C:\Temp\wazuh-agent.msi /q MANAGER_IP=192.168.56.10

# Start service
net start wazuh
```

### Verify in Wazuh Dashboard
- Agents → Should show `win-endpoint` as **Active**
- Security Events → Filter by `agent.name:win-endpoint`

---

## 7. Kali Attacker: Atomic Red Team

```bash
# Update
sudo apt update && sudo apt upgrade -y

# Install Atomic Red Team
sudo apt install -y git powershell
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team

# Install Invoke-AtomicTest module
sudo pwsh -Command "Install-Module -Name invoke-atomicredteam -Scope AllUsers -Force"
```

### Test Connectivity to Windows
```bash
# SMB
smbclient -L //192.168.56.20 -N

# RDP (check port)
nmap -p 3389 192.168.56.20

# WinRM (if enabled on Windows)
# On Windows (Admin): Enable-PSRemoting -Force
# Then from Kali: evil-winrm -i 192.168.56.20 -u USER -p PASS
```

---

## 8. Suricata on Wazuh Manager (Optional but Recommended)

```bash
# Add Suricata repo
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata

# Download ET Open rules
sudo suricata-update enable-source et/open
sudo suricata-update

# Configure for Eve JSON output
# Edit /etc/suricata/suricata.yaml:
# - eve-log: enabled: yes
# - filetype: eve
# - community-id: true

# Start
sudo systemctl enable --now suricata

# Tail alerts
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### Forward Suricata to Wazuh (Filebeat)
```yaml
# /etc/filebeat/modules.d/suricata.yml
- module: suricata
  eve:
    enabled: true
    var.paths: ["/var/log/suricata/eve.json"]
```
```bash
sudo systemctl restart filebeat
```

---

## 9. First Attack Tests (Verify Everything Works)

### Test 1: Brute Force (T1110.001)
```bash
# On Kali
cd atomic-red-team
sudo pwsh -Command "Invoke-AtomicTest T1110.001 -TestNumbers 1"
```

### Test 2: PowerShell Encoded Command (T1059.001)
```bash
sudo pwsh -Command "Invoke-AtomicTest T1059.001 -TestNumbers 1"
```

### Check Wazuh Dashboard
- Security Events → Search: `agent.name:win-endpoint`
- Look for: Rule 5710 (brute force), Rule 92710 (PowerShell suspicious)

---

## 10. Backup / Snapshot Strategy

**After full setup, TAKE SNAPSHOTS:**
```
VirtualBox → Each VM → Snapshots → Take
Name: "Clean Baseline - Post Setup"
```

**Before each attack simulation:**
```
Take snapshot: "Pre-Test-[Technique-ID]"
```

**This lets you revert in 30 seconds instead of rebuilding.**

---

## 11. Common Issues & Fixes

| Issue | Fix |
|-------|-----|
| Wazuh agent not connecting | Check firewall: `sudo ufw allow 1514/tcp 1515/tcp 514/udp` on Wazuh VM |
| Windows logs not showing | Restart Wazuh agent: `Restart-Service wazuh` (Admin PowerShell) |
| Sysmon events missing | Verify config loaded: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" \| Select -First 5` |
| Kali can't reach Windows | Disable Windows Firewall temporarily for lab: `Set-NetFirewallProfile -All -Enabled False` |
| Suricata no alerts | Check rules loaded: `sudo suricata-update && sudo systemctl restart suricata` |

---

## 12. Daily Workflow (After Setup)

```bash
# Morning: Start VMs
VBoxManage startvm "wazuh-manager" --type headless
VBoxManage startvm "win-endpoint" --type headless
VBoxManage startvm "kali-attacker" --type headless

# During day: Wazuh Dashboard at https://192.168.56.10
# Attack from Kali terminal (SSH or console)

# Evening: Snapshot if testing, otherwise just save state
VBoxManage controlvm "wazuh-manager" savestate
VBoxManage controlvm "win-endpoint" savestate
VBoxManage controlvm "kali-attacker" savestate
```

---

**Save this guide to your GitHub repo: `docs/lab-quick-start.md`**