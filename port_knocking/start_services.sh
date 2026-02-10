#!/usr/bin/env bash
# Start both the knock server and protected service

echo "Starting port knocking services..."

# Start the protected service in the background
echo "[1/2] Starting protected service on port 2222..."
python3 protected_service.py &
SERVICE_PID=$!

# Give it a moment to start
sleep 1

# Start the knock server (this runs in foreground)
echo "[2/2] Starting port knock server..."
python3 knock_server.py

# Cleanup on exit
trap "kill $SERVICE_PID 2>/dev/null" EXIT
