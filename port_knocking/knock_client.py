#!/usr/bin/env python3
"""Port knocking client implementation."""

import argparse
import socket
import sys
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_DELAY = 0.5


def send_knock(target, port, delay):
    """Send a single UDP knock to the target port."""
    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        
        # Send knock data (simple payload)
        knock_data = b"KNOCK"
        sock.sendto(knock_data, (target, port))
        
        print(f"  → Knocked on port {port}")
        sock.close()
        
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname {target}")
        sys.exit(1)
    except socket.error as e:
        print(f"[-] Error sending knock to port {port}: {e}")
    
    # Wait before next knock
    time.sleep(delay)


def perform_knock_sequence(target, sequence, delay):
    """Send the full knock sequence."""
    print(f"\n[*] Sending knock sequence to {target}")
    print(f"[*] Sequence: {' → '.join(str(p) for p in sequence)}")
    print()
    
    for i, port in enumerate(sequence, 1):
        print(f"[{i}/{len(sequence)}] Knocking...", end=" ")
        send_knock(target, port, delay)
    
    print(f"\n[+] Knock sequence completed")


def check_protected_port(target, protected_port, wait_time=1.0):
    """Try connecting to the protected port after knocking."""
    print(f"\n[*] Waiting {wait_time}s before checking protected port...")
    time.sleep(wait_time)
    
    print(f"[*] Attempting to connect to port {protected_port}...", end=" ")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        result = sock.connect_ex((target, protected_port))
        sock.close()
        
        if result == 0:
            print(f"\n[+] SUCCESS! Port {protected_port} is now accessible")
            return True
        else:
            print(f"\n[-] Port {protected_port} is still closed (connection refused)")
            return False
            
    except socket.timeout:
        print(f"\n[-] Timeout connecting to port {protected_port}")
        return False
    except socket.error as e:
        print(f"\n[-] Error: {e}")
        return False


def test_wrong_sequence(target, correct_sequence, delay):
    """Test that wrong sequence doesn't open the port."""
    print(f"\n[*] Testing wrong sequence (should fail)...")
    wrong_sequence = [correct_sequence[0], 9999, correct_sequence[2]]
    print(f"[*] Wrong sequence: {' → '.join(str(p) for p in wrong_sequence)}")
    
    for i, port in enumerate(wrong_sequence, 1):
        print(f"[{i}/{len(wrong_sequence)}] Knocking...", end=" ")
        send_knock(target, port, delay)
    
    print(f"\n[+] Wrong sequence sent (port should remain closed)")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Port knocking client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send knock sequence
  python3 knock_client.py --target 172.20.0.40
  
  # Send knock and check if port opens
  python3 knock_client.py --target 172.20.0.40 --check
  
  # Custom sequence
  python3 knock_client.py --target 172.20.0.40 --sequence 1111,2222,3333
  
  # Test wrong sequence
  python3 knock_client.py --target 172.20.0.40 --test-wrong
        """
    )
    parser.add_argument("--target", required=True, help="Target host or IP")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports (default: 1234,5678,9012)",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port (default: 2222)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between knocks in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Attempt connection to protected port after knocking",
    )
    parser.add_argument(
        "--test-wrong",
        action="store_true",
        help="Test with wrong sequence (for demonstration)",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=1.0,
        help="Seconds to wait before checking protected port (default: 1.0)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    
    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")
    
    print("="*60)
    print("Port Knocking Client")
    print("="*60)
    
    if args.test_wrong:
        test_wrong_sequence(args.target, sequence, args.delay)
        if args.check:
            check_protected_port(args.target, args.protected_port, args.wait)
    else:
        perform_knock_sequence(args.target, sequence, args.delay)
        if args.check:
            check_protected_port(args.target, args.protected_port, args.wait)
    
    print("\n" + "="*60)


if __name__ == "__main__":
    main()
