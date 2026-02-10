#!/usr/bin/env python3
"""
Test client for SSH Honeypot
Simulates various attack scenarios without requiring sshpass
"""

import paramiko
import time
import socket
import sys
from datetime import datetime

# Configuration
HONEYPOT_HOST = 'localhost'
HONEYPOT_PORT = 2222

# Test credentials
TEST_USERS = ['root', 'admin', 'test', 'ubuntu', 'user', 'administrator']
TEST_PASSWORDS = ['password', '123456', 'admin', 'toor', '12345678', 'root', 'test']
TEST_COMMANDS = ['whoami', 'uname -a', 'cat /etc/passwd', 'ls -la', 'pwd', 'id', 'ps aux']


def print_section(title):
    """Print a section header"""
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}\n")


def test_connection():
    """Test basic connectivity"""
    print_section("Test 1: Basic Connectivity Check")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((HONEYPOT_HOST, HONEYPOT_PORT))
        sock.close()
        
        if result == 0:
            print(f"Honeypot is running on {HONEYPOT_HOST}:{HONEYPOT_PORT}")
            return True
        else:
            print(f"Cannot connect to {HONEYPOT_HOST}:{HONEYPOT_PORT}")
            print("  Please start the honeypot with: docker compose up honeypot")
            return False
    except Exception as e:
        print(f"Connection error: {e}")
        return False


def test_ssh_authentication(username, password):
    """Attempt SSH authentication"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print(f"  Trying {username}:{password}...", end=' ')
        client.connect(
            hostname=HONEYPOT_HOST,
            port=HONEYPOT_PORT,
            username=username,
            password=password,
            timeout=3,
            look_for_keys=False,
            allow_agent=False
        )
        print("Connected (unexpected!)")
        client.close()
        return True
    except paramiko.AuthenticationException:
        print("Authentication failed (expected)")
        return False
    except Exception as e:
        print(f"Error: {type(e).__name__}")
        return False
    finally:
        client.close()


def test_brute_force():
    """Simulate brute force attack"""
    print_section("Test 2: Brute Force Authentication Attempts")
    
    print(f"Testing {len(TEST_USERS)} usernames with {len(TEST_PASSWORDS)} passwords...")
    
    successful = 0
    total = 0
    
    for username in TEST_USERS:
        for password in TEST_PASSWORDS:
            if test_ssh_authentication(username, password):
                successful += 1
            total += 1
            time.sleep(0.3)  # Small delay between attempts
    
    print(f"\nCompleted {total} authentication attempts")
    print(f"Successful: {successful}, Failed: {total - successful}")


def test_command_execution():
    """Test command execution attempts"""
    print_section("Test 3: Command Execution Attempts")
    
    print("Attempting to execute commands (will fail authentication)...")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Try to connect (will fail, but will log the attempt)
        client.connect(
            hostname=HONEYPOT_HOST,
            port=HONEYPOT_PORT,
            username='admin',
            password='password',
            timeout=3,
            look_for_keys=False,
            allow_agent=False
        )
        
        # If we somehow get here, try commands
        for cmd in TEST_COMMANDS:
            print(f"  Executing: {cmd}")
            stdin, stdout, stderr = client.exec_command(cmd)
            output = stdout.read().decode('utf-8')
            if output:
                print(f"    Output: {output[:100]}")
            time.sleep(0.5)
            
    except paramiko.AuthenticationException:
        print("Authentication failed (expected - commands still logged)")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()


def test_banner_grab():
    """Grab SSH banner"""
    print_section("Test 4: SSH Banner Grabbing")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HONEYPOT_HOST, HONEYPOT_PORT))
        
        banner = sock.recv(1024).decode('utf-8').strip()
        print(f"SSH Banner: {banner}")
        
        if 'OpenSSH' in banner:
            print("Banner looks legitimate")
        else:
            print("Unexpected banner format")
        
        sock.close()
    except Exception as e:
        print(f"Error grabbing banner: {e}")


def test_rapid_connections():
    """Simulate port scanner with rapid connections"""
    print_section("Test 5: Rapid Connection Attempts (Scanner Simulation)")
    
    print("Simulating port scanner with 10 rapid connections...")
    
    for i in range(10):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((HONEYPOT_HOST, HONEYPOT_PORT))
            print(f"  Connection {i+1}: ")
            sock.close()
            time.sleep(0.1)
        except Exception as e:
            print(f"  Connection {i+1}: {type(e).__name__}")


def test_interactive_session():
    """Attempt an interactive session"""
    print_section("Test 6: Interactive Session Simulation")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print("Attempting to establish interactive session...")
        client.connect(
            hostname=HONEYPOT_HOST,
            port=HONEYPOT_PORT,
            username='root',
            password='toor',
            timeout=5,
            look_for_keys=False,
            allow_agent=False
        )
        
        # Open channel
        channel = client.invoke_shell()
        channel.settimeout(2)
        
        # Read welcome message
        time.sleep(1)
        if channel.recv_ready():
            welcome = channel.recv(4096).decode('utf-8', errors='ignore')
            print("Received welcome message:")
            print(welcome[:200])
        
        # Try to send commands
        commands = ['ls', 'pwd', 'whoami']
        for cmd in commands:
            print(f"Sending command: {cmd}")
            channel.send(cmd + '\n')
            time.sleep(0.5)
            if channel.recv_ready():
                response = channel.recv(1024).decode('utf-8', errors='ignore')
                print(f"Response: {response[:100]}")
        
        channel.close()
        
    except paramiko.AuthenticationException:
        print("Authentication failed (expected)")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")
    finally:
        client.close()


def main():
    """Main test routine"""
    print("\n" + "="*60)
    print("SSH Honeypot Test Client")
    print("="*60)
    print(f"Target: {HONEYPOT_HOST}:{HONEYPOT_PORT}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check connectivity first
    if not test_connection():
        print("\nHoneypot is not accessible. Exiting.")
        sys.exit(1)
    
    # Run all tests
    try:
        test_banner_grab()
        time.sleep(1)
        
        test_brute_force()
        time.sleep(1)
        
        test_command_execution()
        time.sleep(1)
        
        test_rapid_connections()
        time.sleep(1)
        
        test_interactive_session()
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    
    # Final summary
    print_section("Testing Complete!")
    print("Check the honeypot logs:")
    print("  Console logs: docker compose logs honeypot")
    print("  JSON logs:    cat honeypot/logs/connections.jsonl")
    print("  General logs: cat honeypot/logs/honeypot.log")
    print("\nAnalyze logs with jq:")
    print("  Total connections:")
    print("    cat honeypot/logs/connections.jsonl | grep '\"event\":\"connected\"' | wc -l")
    print("  Unique IPs:")
    print("    cat honeypot/logs/connections.jsonl | jq -r 'select(.event==\"connected\") | .source_ip' | sort -u")
    print("  Top usernames:")
    print("    cat honeypot/logs/connections.jsonl | jq -r 'select(.event==\"auth_attempt\") | .username' | sort | uniq -c | sort -rn")
    print("  All commands:")
    print("    cat honeypot/logs/connections.jsonl | jq -r 'select(.event==\"command\") | .command'")
    print()


if __name__ == "__main__":
    main()
