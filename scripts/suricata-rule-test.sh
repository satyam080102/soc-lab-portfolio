#!/bin/bash
# Suricata Rule Testing Script
# Tests custom Suricata rules against PCAP or live traffic

set -e

SURICATA_CONF="/etc/suricata/suricata.yaml"
RULES_DIR="/etc/suricata/rules"
CUSTOM_RULES="local.rules"
TEST_PCAP_DIR="/home/kali/test-pcaps"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Suricata Rule Test Framework ===${NC}"

# Function: Validate rule syntax
test_syntax() {
    echo -e "${YELLOW}Testing rule syntax...${NC}"
    sudo suricata -T -c "$SURICATA_CONF" -S "$RULES_DIR/$CUSTOM_RULES" 2>&1 | grep -E "(Error|Warning|OK)"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Syntax OK${NC}"
    else
        echo -e "${RED}✗ Syntax errors found${NC}"
        return 1
    fi
}

# Function: Test against PCAP
test_pcap() {
    local pcap_file="$1"
    local output_dir="/tmp/suricata-test-$(date +%s)"

    if [ ! -f "$pcap_file" ]; then
        echo -e "${RED}PCAP not found: $pcap_file${NC}"
        return 1
    fi

    echo -e "${YELLOW}Testing against PCAP: $pcap_file${NC}"
    mkdir -p "$output_dir"

    sudo suricata -c "$SURICATA_CONF" -S "$RULES_DIR/$CUSTOM_RULES" \
        -r "$pcap_file" -l "$output_dir" --runmode=single 2>&1 | tail -20

    # Check for alerts
    if [ -f "$output_dir/eve.json" ]; then
        alert_count=$(jq 'select(.event_type=="alert") | length' "$output_dir/eve.json" 2>/dev/null || echo "0")
        echo -e "${GREEN}Alerts generated: $alert_count${NC}"

        if [ "$alert_count" -gt 0 ]; then
            echo -e "${YELLOW}Alert details:${NC}"
            jq -c 'select(.event_type=="alert") | {sid: .alert.signature_id, msg: .alert.signature, severity: .alert.severity, src: .src_ip, dst: .dest_ip, proto: .proto}' "$output_dir/eve.json"
        fi
    else
        echo -e "${RED}No eve.json generated${NC}"
    fi

    # Cleanup
    rm -rf "$output_dir"
}

# Function: Generate test PCAPs for each rule
generate_test_pcaps() {
    echo -e "${YELLOW}Generating test PCAPs...${NC}"

    mkdir -p "$TEST_PCAP_DIR"

    # Test 1: PowerShell HTTP beacon
    cat > "$TEST_PCAP_DIR/ps_beacon.pcapng" <<'EOF'
# Use Wireshark to create: HTTP GET /beacon every 60s to 203.0.113.45
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/5.1
EOF

    # Test 2: Large HTTP POST (exfil)
    cat > "$TEST_PCAP_DIR/exfil_post.pcapng" <<'EOF'
# HTTP POST /exfil with 12MB body to 203.0.113.45
# Content-Type: application/octet-stream
EOF

    # Test 3: SMB PsExec
    cat > "$TEST_PCAP_DIR/smb_psexec.pcapng" <<'EOF'
# SMB: Tree Connect IPC$, ADMIN$, C$
# DCERPC: svcctl OpenSCManager, CreateService (PSEXESVC)
# Named Pipe: \pipe\PSEXESVC
EOF

    # Test 4: DNS tunneling
    cat > "$TEST_PCAP_DIR/dns_tunnel.pcapng" <<'EOF'
# DNS TXT queries for high-entropy subdomains
# query: <base64>.malicious.domain
EOF

    echo -e "${GREEN}Test PCAP templates created in $TEST_PCAP_DIR${NC}"
    echo -e "${YELLOW}Use Wireshark/tshark to create actual PCAPs from Atomic tests${NC}"
}

# Function: Run Atomic test and capture PCAP
atomic_test_pcap() {
    local technique="$1"
    local test_num="${2:-1}"
    local output="$TEST_PCAP_DIR/atomic-${technique//\./-}-test${test_num}.pcapng"

    echo -e "${YELLOW}Running Atomic Test $technique Test $test_num with PCAP capture...${NC}"

    # Start tcpdump in background
    sudo tcpdump -i any -w "$output" -s 0 &
    TCPDUMP_PID=$!

    # Give tcpdump time to start
    sleep 2

    # Run Atomic test
    cd /home/kali/atomic-red-team
    sudo pwsh -Command "Invoke-AtomicTest $technique -TestNumbers $test_num"

    # Wait a bit for traffic
    sleep 5

    # Stop tcpdump
    sudo kill $TCPDUMP_PID
    wait $TCPDUMP_PID 2>/dev/null

    echo -e "${GREEN}PCAP saved: $output${NC}"

    # Test rules against it
    test_pcap "$output"
}

# Function: Reload Suricata with new rules
reload_suricata() {
    echo -e "${YELLOW}Reloading Suricata...${NC}"
    sudo systemctl reload suricata
    sleep 2
    sudo systemctl status suricata --no-pager | head -10
}

# Main menu
case "${1:-}" in
    syntax)
        test_syntax
        ;;
    pcap)
        test_pcap "$2"
        ;;
    generate)
        generate_test_pcaps
        ;;
    atomic)
        atomic_test_pcap "$2" "$3"
        ;;
    reload)
        reload_suricata
        ;;
    *)
        echo "Usage: $0 {syntax|pcap <file>|generate|atomic <technique> [test_num]|reload}"
        echo ""
        echo "Examples:"
        echo "  $0 syntax                          # Validate rule syntax"
        echo "  $0 generate                        # Create test PCAP templates"
        echo "  $0 atomic T1059.001 1              # Run Atomic test with PCAP capture"
        echo "  $0 pcap /tmp/test.pcapng           # Test rules against PCAP"
        echo "  $0 reload                          # Reload Suricata after rule changes"
        ;;
esac