#!/usr/bin/env python3
"""Port knocking server implementation."""

import argparse
import logging
import socket
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
DEFAULT_ACCESS_DURATION = 30.0


class KnockState:
    """Track knock progress for a single IP address."""
    
    def __init__(self, sequence_length, window_seconds):
        self.position = 0
        self.start_time = None
        self.sequence_length = sequence_length
        self.window_seconds = window_seconds
        self.locked_until = None
    
    def reset(self):
        """Reset knock progress."""
        self.position = 0
        self.start_time = None
    
    def is_expired(self):
        """Check if the current sequence attempt has expired."""
        if self.start_time is None:
            return False
        return time.time() - self.start_time > self.window_seconds
    
    def is_locked(self):
        """Check if this IP is temporarily locked due to failed attempts."""
        if self.locked_until is None:
            return False
        return time.time() < self.locked_until
    
    def lock(self, duration=5.0):
        """Temporarily lock this IP from making knock attempts."""
        self.locked_until = time.time() + duration
        self.reset()


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def run_command(cmd, check=False):
    """Run a shell command and return the result."""
    logger = logging.getLogger("KnockServer")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=check
        )
        if result.returncode != 0 and result.stderr:
            logger.debug(f"Command failed: {cmd}")
            logger.debug(f"stderr: {result.stderr}")
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.debug(f"Command exception: {cmd} - {e}")
        return False


def setup_iptables(protected_port):
    """Initialize iptables rules to block protected port by default."""
    logger = logging.getLogger("KnockServer")
    
    # Flush existing rules for this port
    run_command(f"iptables -D INPUT -p tcp --dport {protected_port} -j ACCEPT 2>/dev/null")
    run_command(f"iptables -D INPUT -p tcp --dport {protected_port} -j DROP 2>/dev/null")
    
    # Block the protected port by default
    success = run_command(f"iptables -A INPUT -p tcp --dport {protected_port} -j DROP")
    
    if success:
        logger.info(f"Protected port {protected_port} is now blocked by default")
    else:
        logger.warning(f"Failed to set up iptables rules (may need root privileges)")


def open_protected_port(client_ip, protected_port, duration):
    """Open the protected port for a specific IP using firewall rules."""
    logger = logging.getLogger("KnockServer")
    
    # Remove any existing rule for this IP
    run_command(f"iptables -D INPUT -s {client_ip} -p tcp --dport {protected_port} -j ACCEPT 2>/dev/null")
    
    # Add rule to allow this IP
    success = run_command(f"iptables -I INPUT -s {client_ip} -p tcp --dport {protected_port} -j ACCEPT")
    
    if success:
        logger.info(f"[+] Opened port {protected_port} for {client_ip} (duration: {duration}s)")
        
        # Schedule automatic closure
        threading.Timer(duration, close_protected_port, args=(client_ip, protected_port)).start()
    else:
        logger.error(f"Failed to open port {protected_port} for {client_ip}")


def close_protected_port(client_ip, protected_port):
    """Close the protected port for a specific IP using firewall rules."""
    logger = logging.getLogger("KnockServer")
    
    success = run_command(f"iptables -D INPUT -s {client_ip} -p tcp --dport {protected_port} -j ACCEPT 2>/dev/null")
    
    if success:
        logger.info(f"[-] Closed port {protected_port} for {client_ip}")


def listen_for_knocks(sequence, window_seconds, protected_port, access_duration):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info(f"Port Knocking Server started")
    logger.info(f"Knock sequence: {sequence}")
    logger.info(f"Protected port: {protected_port}")
    logger.info(f"Sequence window: {window_seconds}s")
    logger.info(f"Access duration: {access_duration}s")
    
    # Initialize firewall
    setup_iptables(protected_port)
    
    # Track knock progress per IP
    knock_states = defaultdict(lambda: KnockState(len(sequence), window_seconds))
    
    # Create UDP socket for each knock port
    sockets = []
    for port in sequence:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', port))
            sock.settimeout(0.1)
            sockets.append((sock, port))
            logger.info(f"Listening for knocks on UDP port {port}")
        except Exception as e:
            logger.error(f"Failed to bind to port {port}: {e}")
            raise
    
    logger.info("Waiting for knock sequences...")
    
    try:
        while True:
            for sock, port in sockets:
                try:
                    data, addr = sock.recvfrom(1024)
                    client_ip = addr[0]
                    
                    state = knock_states[client_ip]
                    
                    # Check if IP is locked
                    if state.is_locked():
                        logger.debug(f"Ignored knock from locked IP {client_ip}")
                        continue
                    
                    # Check if sequence expired
                    if state.is_expired():
                        logger.warning(f"Sequence expired for {client_ip}, resetting")
                        state.reset()
                    
                    # Start timing on first knock
                    if state.position == 0:
                        state.start_time = time.time()
                    
                    # Check if this is the expected port
                    expected_port = sequence[state.position]
                    
                    if port == expected_port:
                        state.position += 1
                        logger.info(f"Valid knock {state.position}/{len(sequence)} from {client_ip} on port {port}")
                        
                        # Check if sequence is complete
                        if state.position == len(sequence):
                            elapsed = time.time() - state.start_time
                            logger.info(f"[SUCCESS] {client_ip} completed knock sequence in {elapsed:.2f}s")
                            open_protected_port(client_ip, protected_port, access_duration)
                            state.reset()
                    else:
                        # Wrong port in sequence
                        logger.warning(f"Invalid knock from {client_ip} on port {port} (expected {expected_port})")
                        state.lock(duration=5.0)
                        logger.warning(f"IP {client_ip} locked for 5 seconds")
                
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error processing knock: {e}")
    
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        for sock, port in sockets:
            sock.close()


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    parser.add_argument(
        "--access-duration",
        type=float,
        default=DEFAULT_ACCESS_DURATION,
        help="Seconds to keep port open after successful knock",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port, args.access_duration)


if __name__ == "__main__":
    main()
