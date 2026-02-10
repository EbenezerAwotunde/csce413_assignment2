#!/bin/bash

# Test script for SSH Honeypot
# This script simulates various attack scenarios to test the honeypot

echo "================================"
echo "SSH Honeypot Testing Script"
echo "================================"
echo ""

# Configuration
HONEYPOT_HOST="localhost"
HONEYPOT_PORT="2222"

# Check if honeypot is running
echo "[1] Checking if honeypot is accessible..."
nc -z -w 5 $HONEYPOT_HOST $HONEYPOT_PORT
if [ $? -eq 0 ]; then
    echo "✓ Honeypot is running on $HONEYPOT_HOST:$HONEYPOT_PORT"
else
    echo "✗ Honeypot is not accessible. Please start it with: docker compose up honeypot"
    exit 1
fi
echo ""

# Test 1: Basic connection
echo "[2] Test 1: Basic SSH connection attempt..."
echo "Attempting to connect with username 'root' and password 'password'..."
sshpass -p 'password' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $HONEYPOT_PORT root@$HONEYPOT_HOST "whoami" 2>&1 | head -5
echo ""

# Test 2: Multiple authentication attempts
echo "[3] Test 2: Multiple authentication attempts (brute force simulation)..."
usernames=("root" "admin" "test" "ubuntu" "user")
passwords=("password" "123456" "admin" "toor" "12345678")

for user in "${usernames[@]}"; do
    for pass in "${passwords[@]}"; do
        echo "Trying $user:$pass..."
        timeout 2 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -p $HONEYPOT_PORT $user@$HONEYPOT_HOST "exit" 2>/dev/null
        sleep 0.5
    done
done
echo "✓ Completed brute force simulation"
echo ""

# Test 3: Command execution attempts
echo "[4] Test 3: Command execution attempts..."
commands=("whoami" "uname -a" "cat /etc/passwd" "ls -la" "pwd")

for cmd in "${commands[@]}"; do
    echo "Attempting command: $cmd"
    timeout 3 sshpass -p 'test123' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -p $HONEYPOT_PORT admin@$HONEYPOT_HOST "$cmd" 2>/dev/null
    sleep 0.5
done
echo ""

# Test 4: Public key authentication attempt
echo "[5] Test 4: Public key authentication attempt..."
if [ -f ~/.ssh/id_rsa.pub ]; then
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -p $HONEYPOT_PORT -i ~/.ssh/id_rsa test@$HONEYPOT_HOST 2>&1 | head -3
else
    echo "No SSH key found, skipping public key test"
fi
echo ""

# Test 5: Rapid connections (scanner simulation)
echo "[6] Test 5: Rapid connections (port scanner simulation)..."
for i in {1..5}; do
    echo "Connection attempt $i..."
    timeout 1 nc -w 1 $HONEYPOT_HOST $HONEYPOT_PORT < /dev/null
    sleep 0.2
done
echo "✓ Completed scanner simulation"
echo ""

echo "================================"
echo "Testing Complete!"
echo "================================"
echo ""
echo "Check the honeypot logs:"
echo "  - Console logs: docker compose logs honeypot"
echo "  - JSON logs: cat honeypot/logs/connections.jsonl"
echo "  - General logs: cat honeypot/logs/honeypot.log"
echo ""
echo "Analyze the logs with jq:"
echo "  - Total connections: cat honeypot/logs/connections.jsonl | grep '\"event\":\"connected\"' | wc -l"
echo "  - Unique IPs: cat honeypot/logs/connections.jsonl | jq -r 'select(.event==\"connected\") | .source_ip' | sort -u"
echo "  - Top usernames: cat honeypot/logs/connections.jsonl | jq -r 'select(.event==\"auth_attempt\") | .username' | sort | uniq -c | sort -rn"
echo "  - All commands: cat honeypot/logs/connections.jsonl | jq -r 'select(.event==\"command\") | .command'"
echo ""
