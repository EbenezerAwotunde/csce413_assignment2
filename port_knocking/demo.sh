#!/usr/bin/env bash

set -euo pipefail

# Auto-detect container IP if not provided
if [ -z "${1:-}" ]; then
    echo "Auto-detecting port knocking container IP..."
    TARGET_IP=$(sudo docker inspect 2_network_port_knocking 2>/dev/null | grep '"IPAddress"' | grep -v '""' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
    if [ -z "$TARGET_IP" ]; then
        echo "ERROR: Could not detect container IP. Is the container running?"
        echo "Usage: $0 [TARGET_IP] [SEQUENCE] [PORT]"
        exit 1
    fi
    echo "Detected IP: $TARGET_IP"
else
    TARGET_IP=$1
fi

SEQUENCE=${2:-"1234,5678,9012"}
PROTECTED_PORT=${3:-2222}

echo ""
echo "============================================================"
echo "Port Knocking Demonstration"
echo "============================================================"
echo "Target: $TARGET_IP"
echo "Knock Sequence: $SEQUENCE"
echo "Protected Port: $PROTECTED_PORT (TCP Service)"
echo "Access Duration: 30 seconds after successful knock"
echo "============================================================"
echo ""

echo "[Step 1/5] Testing port BEFORE knocking (should fail)"
echo "-----------------------------------------------------------"
timeout 3 nc -zv $TARGET_IP $PROTECTED_PORT 2>&1 | grep -i "refused\|timeout\|failed" && echo "✓ Port is blocked (expected)" || echo "Note: Port check completed"
echo ""

echo "[Step 2/5] Testing WRONG knock sequence (should not open port)"
echo "-----------------------------------------------------------"
python3 knock_client.py --target "$TARGET_IP" --sequence "1234,9999,9012" --test-wrong
sleep 1
echo ""

echo "[Step 3/5] Sending CORRECT knock sequence"
echo "-----------------------------------------------------------"
python3 knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE" --check --wait 2
echo ""

echo "[Step 4/5] Testing connection AFTER knocking (should work within 30s)"
echo "-----------------------------------------------------------"
echo "Attempting to connect to protected service..."
echo "Note: You have 30 seconds after knocking to connect"
echo ""

# Try to connect and get the response
echo "Connecting with netcat:"
timeout 5 nc $TARGET_IP $PROTECTED_PORT 2>&1 || echo "Note: Connection attempt completed"
echo ""
echo "[Step 5/5] Manual Connection Instructions"
echo "-----------------------------------------------------------"
echo "The firewall will automatically close port $PROTECTED_PORT after 30 seconds."
echo ""
echo "To manually connect after knocking, run:"
echo "  cd port_knocking"
echo "  python3 knock_client.py --target $TARGET_IP --sequence $SEQUENCE && nc $TARGET_IP $PROTECTED_PORT"
echo ""
echo "Or use the one-liner:"
echo "  python3 knock_client.py --target $TARGET_IP && nc $TARGET_IP $PROTECTED_PORT"
echo ""

echo "============================================================"
echo "Demonstration Complete!"
echo "============================================================"


