#!/usr/bin/env python3
"""SSH Honeypot Implementation"""

import socket
import threading
import paramiko
import logging
import sys
import time
from datetime import datetime
from logger import HoneypotLogger

# SSH Server Configuration
HOST = '0.0.0.0'
PORT = 22
BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

# Generate server key
host_key = paramiko.RSAKey.generate(2048)


class SSHServerHandler(paramiko.ServerInterface):
    """Custom SSH server handler for the honeypot"""
    
    def __init__(self, client_address, honeypot_logger):
        self.client_address = client_address
        self.logger = honeypot_logger
        self.auth_attempts = []
        self.event = threading.Event()
        
    def check_auth_password(self, username, password):
        """Log authentication attempts and always reject"""
        self.logger.log_auth_attempt(
            self.client_address,
            username,
            password,
            'password'
        )
        self.auth_attempts.append({
            'username': username,
            'password': password,
            'method': 'password',
            'timestamp': datetime.now().isoformat()
        })
        
        # Always reject, but add small delay to seem realistic
        time.sleep(0.5)
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """Log public key authentication attempts and reject"""
        self.logger.log_auth_attempt(
            self.client_address,
            username,
            f"PublicKey:{key.get_name()}",
            'publickey'
        )
        self.auth_attempts.append({
            'username': username,
            'key_type': key.get_name(),
            'method': 'publickey',
            'timestamp': datetime.now().isoformat()
        })
        return paramiko.AUTH_FAILED
    
    def check_channel_request(self, kind, chanid):
        """Allow channel requests to seem legitimate"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        """Allow shell requests"""
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, 
                                   pixelwidth, pixelheight, modes):
        """Allow PTY requests"""
        return True
    
    def check_channel_exec_request(self, channel, command):
        """Log command execution attempts"""
        self.logger.log_command(self.client_address, command.decode('utf-8', errors='ignore'))
        return True
    
    def get_allowed_auths(self, username):
        """Advertise available authentication methods"""
        return 'password,publickey'


def handle_connection(client_socket, client_address, honeypot_logger):
    """Handle individual SSH connection"""
    connection_start = datetime.now()
    
    try:
        # Log the connection
        honeypot_logger.log_connection(client_address, 'connected')
        
        # Create SSH transport
        transport = paramiko.Transport(client_socket)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        
        # Create server handler
        server_handler = SSHServerHandler(client_address, honeypot_logger)
        
        try:
            transport.start_server(server=server_handler)
        except paramiko.SSHException as e:
            honeypot_logger.logger.warning(f"SSH negotiation failed from {client_address}: {e}")
            return
        
        # Accept channel
        channel = transport.accept(20)
        
        if channel is not None:
            # Send fake shell prompt
            channel.send(b'Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)\r\n')
            channel.send(b'\r\n')
            channel.send(b' * Documentation:  https://help.ubuntu.com\r\n')
            channel.send(b' * Management:     https://landscape.canonical.com\r\n')
            channel.send(b' * Support:        https://ubuntu.com/advantage\r\n')
            channel.send(b'\r\n')
            
            # Collect commands for a short time
            commands = []
            channel.settimeout(1.0)
            
            try:
                while True:
                    data = channel.recv(1024)
                    if len(data) == 0:
                        break
                    
                    command = data.decode('utf-8', errors='ignore').strip()
                    if command:
                        commands.append(command)
                        honeypot_logger.log_command(client_address, command)
                        
                        # Send fake response
                        channel.send(f"bash: {command}: command not found\r\n".encode())
                        channel.send(b'$ ')
                        
            except socket.timeout:
                pass
            except Exception as e:
                honeypot_logger.logger.debug(f"Channel communication error: {e}")
            
            channel.close()
        
    except Exception as e:
        honeypot_logger.logger.error(f"Error handling connection from {client_address}: {e}")
    
    finally:
        connection_end = datetime.now()
        duration = (connection_end - connection_start).total_seconds()
        
        # Log disconnection with full session details
        honeypot_logger.log_connection(
            client_address, 
            'disconnected',
            duration=duration
        )
        
        try:
            transport.close()
        except:
            pass
        
        try:
            client_socket.close()
        except:
            pass


def run_honeypot():
    """Main honeypot server loop"""
    # Initialize logger
    honeypot_logger = HoneypotLogger()
    
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(100)
        
        honeypot_logger.logger.info(f"SSH Honeypot listening on {HOST}:{PORT}")
        honeypot_logger.logger.info(f"Banner: {BANNER}")
        
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                honeypot_logger.logger.info(f"New connection from {client_address[0]}:{client_address[1]}")
                
                # Handle each connection in a separate thread
                client_thread = threading.Thread(
                    target=handle_connection,
                    args=(client_socket, client_address, honeypot_logger)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except KeyboardInterrupt:
                honeypot_logger.logger.info("Shutting down honeypot...")
                break
            except Exception as e:
                honeypot_logger.logger.error(f"Error accepting connection: {e}")
                
    finally:
        server_socket.close()
        honeypot_logger.logger.info("Honeypot stopped")


if __name__ == "__main__":
    run_honeypot()
