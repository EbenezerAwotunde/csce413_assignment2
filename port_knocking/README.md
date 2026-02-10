## Port Knocking Implementation

A complete port knocking system that uses a secret knock sequence to control access to a protected TCP service.

### Overview

Port knocking is a security technique where a service port remains closed until a client sends a specific sequence of connection attempts (knocks) to predefined ports. This implementation provides:

- **Knock Server**: Listens for knock sequences and manages firewall rules
- **Protected Service**: Simple TCP service on port 2222 (blocked by default)
- **Knock Client**: Sends knock sequences to gain access
- **Automatic Security**: Wrong sequences trigger temporary IP lockouts

### Architecture

```
Client                    Knock Server              Protected Service (Port 2222)
  │                            │                           │
  ├──── Knock Port 1234 ──────>│                           │
  ├──── Knock Port 5678 ──────>│                           │
  ├──── Knock Port 9012 ──────>│                           │
  │                            │                           │
  │                            │── Open Firewall ──>       │
  │                            │   (for client IP)         │
  │                                                         │
  ├──── Connect to Port 2222 ─────────────────────────────>│
  │<──── Welcome Message + FLAG ─────────────────────────────┤
  │                                                         │
  │                            │── Auto-close after 30s ──>│
```

### Configuration

**Default Settings:**
- Knock sequence: `1234, 5678, 9012`
- Protected port: `2222`
- Sequence window: `10 seconds` (time to complete sequence)
- Access duration: `30 seconds` (port stays open)
- Lockout duration: `5 seconds` (after wrong sequence)

### Features

#### Knock Server (`knock_server.py`)
- ✓ Listens on UDP ports for knock sequences
- ✓ Tracks each client IP independently
- ✓ Enforces timing constraints (10-second window)
- ✓ Uses iptables to control firewall rules
- ✓ Automatically closes port after access expires
- ✓ Locks out IPs that send wrong sequences
- ✓ Per-IP state tracking

#### Knock Client (`knock_client.py`)
- ✓ Sends UDP knock packets in sequence
- ✓ Configurable delay between knocks
- ✓ Can verify if port opens after knocking
- ✓ Supports testing wrong sequences
- ✓ Clear status reporting

#### Protected Service (`protected_service.py`)
- ✓ Simple TCP server on port 2222
- ✓ Returns welcome message and flag
- ✓ Firewall-controlled access
- ✓ No authentication required (security is port knocking)

### Usage

#### Starting the Server

Run from the repository root:
```bash
docker compose up port_knocking
```

Or manually:
```bash
python3 knock_server.py
```

Custom configuration:
```bash
python3 knock_server.py --sequence 1111,2222,3333 --protected-port 8080 --window 15 --access-duration 60
```

#### Using the Client

Basic knock (from host machine):
```bash
cd port_knocking
python3 knock_client.py --target 172.21.0.40
```

Knock and verify access:
```bash
python3 knock_client.py --target 172.21.0.40 --check
```

Knock and connect (recommended):
```bash
python3 knock_client.py --target 172.21.0.40 --sequence 1234,5678,9012 && nc 172.21.0.40 2222
```

Custom sequence:
```bash
python3 knock_client.py --target 172.21.0.40 --sequence 1111,2222,3333
```

Test wrong sequence (demonstrates lockout):
```bash
python3 knock_client.py --target 172.21.0.40 --test-wrong
```

#### Running the Demo

The demo script automatically detects the container IP and shows the complete workflow:
```bash
cd port_knocking
chmod +x demo.sh
./demo.sh
```

Or specify the IP manually:
```bash
./demo.sh 172.21.0.40
```

This will:
1. Try connecting before knocking (fails)
2. Send wrong sequence (gets locked out)
3. Send correct sequence (port opens)
4. Verify port is accessible
5. Show how to connect manually with netcat

### Security Features

1. **Timing Enforcement**: Must complete sequence within 10 seconds
2. **Wrong Sequence Lockout**: 5-second ban after incorrect knock
3. **Per-IP Tracking**: Each client tracked independently  
4. **Automatic Expiration**: Access expires after 30 seconds
5. **Firewall Integration**: Uses iptables for real protection
6. **UDP Knocks**: Stealthy, no TCP handshake

### How It Works

1. **Server Initialization**:
   - Starts protected TCP service on port 2222
   - Binds UDP sockets to knock ports (1234, 5678, 9012)
   - Sets up iptables to block port 2222 by default

2. **Client Knocking**:
   - Sends UDP packets to each port in sequence
   - Server tracks progress per source IP

3. **Sequence Validation**:
   - Server verifies each knock is to the correct port
   - Checks sequence is completed within time window
   - On wrong port: locks out IP for 5 seconds

4. **Access Granted**:
   - Server adds iptables rule: `iptables -I INPUT -s <client_ip> -p tcp --dport 2222 -j ACCEPT`
   - Client can now connect to port 2222
   - Rule auto-removed after 30 seconds

5. **Connection**:
   - Client connects: `nc 172.21.0.40 2222`
   - Service sends welcome message and flag
   - Connection closes automatically

### Testing from Outside Container

```bash
# Install client dependencies (if needed)
# None required - uses standard Python socket library

# Get container IP (auto-detect)
cd port_knocking
./demo.sh

# Or knock from host manually
python3 knock_client.py --target 172.21.0.40 --check

# Connect with netcat (within 30 seconds of knocking)
nc 172.21.0.40 2222

# Or do it all in one command
python3 knock_client.py --target 172.21.0.40 && nc 172.21.0.40 2222
```

### Troubleshooting

**Port still blocked after knocking:**
- Check server logs for sequence completion: `docker logs 2_network_port_knocking`
- Verify you're using the correct sequence (1234,5678,9012)
- Ensure you complete sequence within 10 seconds
- Check container IP is correct: `docker inspect 2_network_port_knocking | grep IPAddress`

**Connection refused after knocking:**
- Make sure you knocked within the last 30 seconds
- Verify port opens after knock: use `--check` flag
- Try with netcat: `nc -v 172.21.0.40 2222`

**"Permission denied" on server:**
- Server needs root/CAP_NET_ADMIN for iptables
- Docker container has `cap_add: NET_ADMIN` in compose file

**Client can't send knocks:**
- Check network connectivity: `ping 172.21.0.40`
- Verify Docker network is up: `docker network ls`
- Confirm container is running: `docker ps | grep port_knocking`

**Port closes immediately:**
- By design - access expires after 30 seconds
- Send knock sequence again to regain access

### Files

- `knock_server.py` - Main server implementation
- `knock_client.py` - Client for sending knocks
- `protected_service.py` - Simple TCP service on protected port
- `start_services.sh` - Starts protected service and knock server
- `demo.sh` - Demonstration script with auto-detection
- `test_knocking.sh` - Quick test script
- `Dockerfile` - Container configuration
- `README.md` - This file

### Network Details

- Container IP: `172.21.0.40` (auto-assigned by Docker)
- Network: `vulnerable_network`
- Capabilities: `NET_ADMIN` (for iptables)
- Protected Port: `2222` (TCP service, blocked by default)

### Example Output

```
============================================================
Port Knocking Client
============================================================

[*] Sending knock sequence to 172.21.0.40
[*] Sequence: 1234 → 5678 → 9012

[1/3] Knocking...   → Knocked on port 1234
[2/3] Knocking...   → Knocked on port 5678
[3/3] Knocking...   → Knocked on port 9012

[+] Knock sequence completed

[*] Waiting 1.0s before checking protected port...
[*] Attempting to connect to port 2222... 
[+] SUCCESS! Port 2222 is now accessible

============================================================

# Now connect to the service:
$ nc 172.21.0.40 2222
Welcome to the protected service!
You successfully knocked and gained access.
FLAG{port_knock1ng_m4st3r_2024}
Connection will close in 3 seconds...
```

### Advanced Usage

**Monitor server logs:**
```bash
docker logs -f 2_network_port_knocking
```

**Check iptables rules:**
```bash
docker exec 2_network_port_knocking iptables -L INPUT -n -v
```

**Manual knock (without client):**
```bash
# Send UDP packets to each port
echo "KNOCK" | nc -u -w1 172.21.0.40 1234
echo "KNOCK" | nc -u -w1 172.21.0.40 5678
echo "KNOCK" | nc -u -w1 172.21.0.40 9012

# Then connect to the service
nc 172.21.0.40 2222
```

### Implementation Notes

- Uses UDP for knocks (stealthy, no connection state)
- Thread-safe state management per client IP
- Automatic cleanup on timeout/expiration
- Comprehensive logging for debugging
- Supports multiple simultaneous clients

