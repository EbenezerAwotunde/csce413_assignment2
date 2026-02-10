#!/usr/bin/env python3
"""A simple protected service that runs on port 2222."""

import socket
import threading
import time


def handle_client(conn, addr):
    """Handle a client connection."""
    try:
        conn.send(b"Welcome to the protected service!\n")
        conn.send(b"You successfully knocked and gained access.\n")
        conn.send(b"FLAG{port_knock1ng_m4st3r_2024}\n")
        conn.send(b"Connection will close in 3 seconds...\n")
        time.sleep(3)
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()


def main():
    """Run the protected service."""
    host = '0.0.0.0'
    port = 2222
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    
    print(f"Protected service listening on port {port}")
    print("Note: Access is controlled by firewall rules")
    print("Waiting for connections...")
    
    try:
        while True:
            conn, addr = sock.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]}")
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
