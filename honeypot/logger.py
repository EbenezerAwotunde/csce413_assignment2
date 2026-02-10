"""Logging helpers for the honeypot."""

import json
import logging
import os
from datetime import datetime
from collections import defaultdict


class HoneypotLogger:
    """Structured logging for SSH honeypot"""
    
    def __init__(self, log_dir="/app/logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Set up standard logging
        self.logger = logging.getLogger("SSHHoneypot")
        self.logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler for general logs
        file_handler = logging.FileHandler(f"{log_dir}/honeypot.log")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(console_formatter)
        self.logger.addHandler(file_handler)
        
        # JSONL file for structured connection logs
        self.connections_file = f"{log_dir}/connections.jsonl"
        
        # Track statistics
        self.stats = {
            'total_connections': 0,
            'auth_attempts': defaultdict(int),
            'usernames': defaultdict(int),
            'passwords': defaultdict(int),
            'source_ips': defaultdict(int),
            'commands': defaultdict(int)
        }
        
        self.logger.info("HoneypotLogger initialized")
    
    def log_connection(self, client_address, event, duration=None):
        """Log a connection event"""
        self.stats['total_connections'] += 1
        self.stats['source_ips'][client_address[0]] += 1
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'source_ip': client_address[0],
            'source_port': client_address[1],
            'duration': duration
        }
        
        # Write to JSONL file
        with open(self.connections_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        if event == 'connected':
            self.logger.info(f"Connection established from {client_address[0]}:{client_address[1]}")
        elif event == 'disconnected':
            self.logger.info(f"Connection closed from {client_address[0]}:{client_address[1]} (duration: {duration:.2f}s)")
    
    def log_auth_attempt(self, client_address, username, credential, method):
        """Log an authentication attempt"""
        self.stats['auth_attempts'][method] += 1
        self.stats['usernames'][username] += 1
        
        if method == 'password':
            self.stats['passwords'][credential] += 1
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': 'auth_attempt',
            'source_ip': client_address[0],
            'source_port': client_address[1],
            'username': username,
            'credential': credential,
            'method': method,
            'result': 'failed'
        }
        
        # Write to JSONL file
        with open(self.connections_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        self.logger.warning(
            f"Authentication attempt from {client_address[0]}: "
            f"username='{username}' credential='{credential}' method={method}"
        )
        
        # Alert on suspicious patterns
        self._check_alerts(client_address, username, credential)
    
    def log_command(self, client_address, command):
        """Log a command execution attempt"""
        self.stats['commands'][command] += 1
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': 'command',
            'source_ip': client_address[0],
            'source_port': client_address[1],
            'command': command
        }
        
        # Write to JSONL file
        with open(self.connections_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        self.logger.warning(f"Command from {client_address[0]}: {command}")
    
    def _check_alerts(self, client_address, username, credential):
        """Check for suspicious patterns and generate alerts"""
        # Alert on common attack patterns
        suspicious_usernames = ['root', 'admin', 'administrator', 'test', 'oracle', 'postgres']
        if username.lower() in suspicious_usernames:
            self.logger.error(f"ALERT: Suspicious username '{username}' from {client_address[0]}")
        
        # Alert on common passwords
        common_passwords = ['password', '123456', 'admin', 'root', 'toor', '12345678']
        if credential.lower() in common_passwords:
            self.logger.error(f"ALERT: Common password attempt '{credential}' from {client_address[0]}")
        
        # Alert on multiple attempts from same IP
        if self.stats['source_ips'][client_address[0]] > 5:
            self.logger.error(f"ALERT: Multiple connection attempts from {client_address[0]} ({self.stats['source_ips'][client_address[0]]} total)")
    
    def get_statistics(self):
        """Return current statistics"""
        return {
            'total_connections': self.stats['total_connections'],
            'unique_ips': len(self.stats['source_ips']),
            'auth_attempts': dict(self.stats['auth_attempts']),
            'top_usernames': dict(sorted(self.stats['usernames'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_passwords': dict(sorted(self.stats['passwords'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ips': dict(sorted(self.stats['source_ips'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_commands': dict(sorted(self.stats['commands'].items(), key=lambda x: x[1], reverse=True)[:10])
        }
    
    def print_statistics(self):
        """Print current statistics"""
        stats = self.get_statistics()
        self.logger.info("=== Honeypot Statistics ===")
        self.logger.info(f"Total Connections: {stats['total_connections']}")
        self.logger.info(f"Unique IPs: {stats['unique_ips']}")
        self.logger.info(f"Authentication Attempts: {stats['auth_attempts']}")
        self.logger.info(f"Top Usernames: {stats['top_usernames']}")
        self.logger.info(f"Top Passwords: {stats['top_passwords']}")
        self.logger.info(f"Top Source IPs: {stats['top_ips']}")
        self.logger.info(f"Top Commands: {stats['top_commands']}")
