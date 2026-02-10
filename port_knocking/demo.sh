#!/usr/bin/env bash

set -euo pipefail

TARGET_IP=${1:-172.20.0.40}
SEQUENCE=${2:-"1234,5678,9012"}
PROTECTED_PORT=${3:-2222}

echo "============================================================"
echo "Port Knocking Demonstration"
echo "============================================================"
echo "Target: $TARGET_IP"
echo "Knock Sequence: $SEQUENCE"
echo "Protected Port: $PROTECTED_PORT"
echo "============================================================"
echo ""

echo "[Step 1/4] Testing protected port BEFORE knocking (should fail)"
echo "-----------------------------------------------------------"
timeout 3 nc -zv "$TARGET_IP" "$PROTECTED_PORT" 2>&1 || echo "✓ Port is closed (expected)"
echo ""

echo "[Step 2/4] Testing WRONG knock sequence (should not open port)"
echo "-----------------------------------------------------------"
python3 knock_client.py --target "$TARGET_IP" --sequence "1234,9999,9012" --test-wrong
echo ""

echo "[Step 3/4] Sending CORRECT knock sequence"
echo "-----------------------------------------------------------"
python3 knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE" --check --wait 2
echo ""

echo "[Step 4/4] Waiting for access to expire (30 seconds)..."
echo "-----------------------------------------------------------"
echo "The port will automatically close after the access duration expires."
echo "You can test again with: python3 knock_client.py --target $TARGET_IP --check"
echo ""

echo "============================================================"
echo "Demonstration Complete!"
echo "============================================================"


