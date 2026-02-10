# SSH Honeypot Implementation

## Overview

This is a fully functional SSH honeypot designed to detect, log, and analyze unauthorized access attempts. It simulates an Ubuntu SSH server running OpenSSH 8.2p1, appearing legitimate to attackers while logging all interactions.

## Features

### Core Functionality
- **Realistic SSH Server Simulation** - Proper SSH protocol implementation using Paramiko
- **Authentic Service Banner** - Mimics OpenSSH 8.2p1 Ubuntu
- **Multi-threaded** - Handles multiple concurrent connections
- **Comprehensive Logging** - Records all connection attempts, authentication tries, and commands
- **Structured Data Format** - JSONL output for easy parsing and analysis
- **Real-time Alerts** - Detects suspicious patterns and generates warnings

### Authentication Handling
- Accepts both password and public key authentication methods
- Always rejects authentication (maintains deception)
- Logs all credentials attempted
- Adds realistic delays to avoid detection

### Interaction Capabilities
- Provides fake shell prompt after connection
- Displays realistic system information banner
- Accepts and logs command input
- Sends fake command responses
- Tracks session duration

## Architecture

### Components

1. **honeypot.py** - Main SSH server implementation
   - Socket server listening on port 22
   - Paramiko-based SSH protocol handling
   - Connection threading for concurrent sessions
   - Session management and interaction

2. **logger.py** - Logging and analytics module
   - Structured logging to JSONL format
   - Real-time statistics tracking
   - Alert generation for suspicious patterns
   - Multiple output formats (console + file)

3. **Dockerfile** - Container configuration
   - Python 3.11 base image
   - Paramiko and cryptography libraries
   - Log directory setup
   - Port exposure

## Installation & Usage

### Using Docker Compose (Recommended)

From the repository root:

```bash
# Build and start the honeypot
docker compose up --build honeypot

# Run in background
docker compose up -d honeypot

# View logs
docker compose logs -f honeypot

# Stop the honeypot
docker compose down
```

### Standalone Docker

```bash
cd honeypot/

# Build the image
docker build -t ssh-honeypot .

# Run the container
docker run -d \
  -p 22:22 \
  -v $(pwd)/logs:/app/logs \
  --name ssh-honeypot \
  ssh-honeypot

# View logs
docker logs -f ssh-honeypot
```

### Local Python (Development)

```bash
cd honeypot/

# Install dependencies
pip install paramiko cryptography

# Run the honeypot (requires root for port 22)
sudo python3 honeypot.py
```

## Testing the Honeypot

### Basic Connection Test

```bash
# From another terminal/machine
ssh admin@localhost

# Try various credentials
# Username: root, admin, test, ubuntu
# Password: password, 123456, admin
```

### Automated Attack Simulation

```bash
# Install hydra (brute force tool)
sudo apt-get install hydra

# Create password list
echo -e "password\n123456\nadmin\nroot\ntoor" > passwords.txt

# Run brute force test
hydra -l root -P passwords.txt ssh://localhost

# Check honeypot logs
cat logs/connections.jsonl
cat logs/honeypot.log
```

### Command Execution Test

```bash
# Connect with SSH client
ssh test@localhost

# After entering credentials, try commands:
whoami
ls -la
cat /etc/passwd
uname -a
```

## Log Format

### Connection Log (JSONL)

Each line in `logs/connections.jsonl` is a JSON object:

**Connection Event:**
```json
{
  "timestamp": "2026-02-09T10:15:32.123456",
  "event": "connected",
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "duration": null
}
```

**Authentication Attempt:**
```json
{
  "timestamp": "2026-02-09T10:15:33.456789",
  "event": "auth_attempt",
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "username": "root",
  "credential": "password123",
  "method": "password",
  "result": "failed"
}
```

**Command Execution:**
```json
{
  "timestamp": "2026-02-09T10:15:35.789012",
  "event": "command",
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "command": "whoami"
}
```

**Disconnection:**
```json
{
  "timestamp": "2026-02-09T10:15:45.345678",
  "event": "disconnected",
  "source_ip": "192.168.1.100",
  "source_port": 54321,
  "duration": 13.22
}
```

### General Log (honeypot.log)

Human-readable format with timestamps and severity levels:

```
2026-02-09 10:15:32,123 - SSHHoneypot - INFO - SSH Honeypot listening on 0.0.0.0:22
2026-02-09 10:15:32,124 - SSHHoneypot - INFO - Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
2026-02-09 10:15:33,456 - SSHHoneypot - WARNING - Authentication attempt from 192.168.1.100: username='root' credential='password123' method=password
2026-02-09 10:15:35,789 - SSHHoneypot - WARNING - Command from 192.168.1.100: whoami
2026-02-09 10:15:35,790 - SSHHoneypot - ERROR - ALERT: Suspicious username 'root' from 192.168.1.100
```

## Security Considerations

### What Makes This Convincing

1. **Authentic SSH Protocol** - Full SSH v2 implementation via Paramiko
2. **Realistic Banner** - Matches actual Ubuntu OpenSSH installations
3. **Proper Authentication Flow** - Accepts auth methods, provides rejections with proper timing
4. **Fake Shell Environment** - Displays system info, accepts commands, provides responses
5. **Behavioral Realism** - Adds delays, sends proper SSH messages

### Limitations

- **Not a Full Shell** - Limited command interaction
- **No Persistent Sessions** - Sessions timeout relatively quickly
- **Fixed Responses** - Command output is generic
- **No Filesystem** - Cannot navigate directories or view files
- **Detection Possible** - Advanced attackers with custom tools might detect anomalies

### Ethical and Legal Considerations

**Important:**
- Only deploy on networks you own or have explicit permission to monitor
- Ensure compliance with local laws regarding interception of communications
- Consider privacy implications of logging attacker credentials
- Use for educational and defensive purposes only
- Never use logged credentials for unauthorized access

## Analysis

See [analysis.md](analysis.md) for detailed analysis of captured attacks, including:
- Common attack patterns
- Credential statistics
- Behavioral analysis
- Security recommendations

## Advanced Features

### Statistics Tracking

The logger tracks:
- Total connection count
- Unique source IPs
- Authentication attempt methods
- Most common usernames
- Most common passwords
- Most attempted commands

### Alert System

Automatic alerts trigger on:
- Suspicious usernames (root, admin, administrator, etc.)
- Common passwords (password, 123456, admin, etc.)
- Multiple connections from same IP (>5)

### Log Analysis

Parse JSONL logs with tools like `jq`:

```bash
# Count total connections
cat logs/connections.jsonl | grep '"event":"connected"' | wc -l

# List unique IPs
cat logs/connections.jsonl | jq -r 'select(.event=="connected") | .source_ip' | sort -u

# Top 10 usernames
cat logs/connections.jsonl | jq -r 'select(.event=="auth_attempt") | .username' | sort | uniq -c | sort -rn | head -10

# Top 10 passwords
cat logs/connections.jsonl | jq -r 'select(.event=="auth_attempt") | .credential' | sort | uniq -c | sort -rn | head -10

# List all commands attempted
cat logs/connections.jsonl | jq -r 'select(.event=="command") | .command'
```

## Future Enhancements

Potential improvements:
- [ ] Fake filesystem implementation
- [ ] More realistic command responses
- [ ] Session recording (full terminal capture)
- [ ] Multiple protocol support (FTP, Telnet, HTTP)
- [ ] Webhook/email alerts
- [ ] Integration with threat intelligence feeds
- [ ] Machine learning for attack pattern detection
- [ ] Web dashboard for log visualization

## Troubleshooting

### Port 22 Already in Use

If you have SSH running on port 22:

```bash
# Option 1: Stop existing SSH
sudo systemctl stop ssh

# Option 2: Change honeypot port in docker-compose.yml
ports:
  - "2222:22"  # Map host port 2222 to container port 22
```

### Permission Denied

Port 22 requires root privileges:

```bash
# Use sudo for local execution
sudo python3 honeypot.py

# Or use Docker (recommended)
docker compose up honeypot
```

### No Logs Generated

Check log directory permissions:

```bash
# Create logs directory
mkdir -p logs

# Set permissions
chmod 777 logs

# Verify logs are being written
docker exec -it <container_name> ls -la /app/logs/
```

### Connection Refused

Ensure the container is running:

```bash
# Check container status
docker compose ps

# View container logs
docker compose logs honeypot

# Check if port is exposed
docker port <container_name>
```

## Resources

- **Paramiko Documentation**: https://www.paramiko.org/
- **SSH Protocol**: https://www.rfc-editor.org/rfc/rfc4253
- **Honeypot Research**: https://www.honeynet.org/
- **Similar Projects**: 
  - Cowrie: https://github.com/cowrie/cowrie
  - Dionaea: https://github.com/DinoTools/dionaea

## License

This is educational software for Assignment 2 of CSCE 413. Use responsibly and ethically.
