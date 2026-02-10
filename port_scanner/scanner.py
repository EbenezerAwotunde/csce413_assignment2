#!/usr/bin/env python3
'''
To find docker bridge interface for network scanning: `ip link show | grep br-`
Output: br-3be1277dc120
'''

import socket
import sys
import argparse
import threading
import ipaddress
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time


class PortScanner:
    def __init__(self, timeout=1.0, max_threads=100, verbose=False):
        """
        Initialize the port scanner
        
        Args:
            timeout (float): Connection timeout in seconds
            max_threads (int): Maximum number of concurrent threads
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose
        self.results = []
        self.lock = threading.Lock()
    
    def scan_port(self, target, port):
        """
        Scan a single port on the target host
        
        Args:
            target (str): IP address or hostname to scan
            port (int): Port number to scan
        
        Returns:
            dict: Result dictionary with port, state, and banner info
        """
        result = {
            'port': port,
            'state': 'closed',
            'service': '',
            'banner': ''
        }
        
        try:
            # Create a TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try to connect
            connection_result = sock.connect_ex((target, port))
            
            if connection_result == 0:
                result['state'] = 'open'
                
                # Try to grab banner
                try:
                    # Send a generic probe
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    result['banner'] = banner
                    result['service'] = self.identify_service(port, banner)
                except:
                    # If banner grabbing fails, just identify by port
                    result['service'] = self.identify_service(port, '')
                
                if self.verbose:
                    print(f"[+] Port {port} is open - {result['service']}")
            
            sock.close()
            
        except socket.timeout:
            pass
        except socket.error:
            pass
        except Exception as e:
            if self.verbose:
                print(f"Error scanning port {port}: {e}")
        
        return result
    
    def identify_service(self, port, banner):
        """
        Identify service based on port number and banner
        
        Args:
            port (int): Port number
            banner (str): Service banner
        
        Returns:
            str: Identified service name
        """
        # Common port mappings
        common_ports = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5000: 'UPnP',
            5001: 'HTTP/Flask',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
        }
        
        # Check banner for service identification
        if banner:
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                return f"SSH ({banner[:50]})"
            elif 'http' in banner_lower or 'html' in banner_lower:
                return f"HTTP ({banner[:50]})"
            elif 'ftp' in banner_lower:
                return f"FTP ({banner[:50]})"
            elif 'smtp' in banner_lower:
                return f"SMTP ({banner[:50]})"
            elif 'mysql' in banner_lower:
                return f"MySQL ({banner[:50]})"
            elif 'redis' in banner_lower:
                return f"Redis ({banner[:50]})"
        
        # Fall back to common port mapping
        return common_ports.get(port, 'Unknown')
    
    def scan_range(self, target, start_port, end_port):
        """
        Scan a range of ports on the target host using multi-threading
        
        Args:
            target (str): IP address or hostname to scan
            start_port (int): Starting port number
            end_port (int): Ending port number
        
        Returns:
            list: List of open ports with details
        """
        print(f"\n[*] Scanning {target} from port {start_port} to {end_port}")
        print(f"[*] Using {self.max_threads} threads with {self.timeout}s timeout")
        print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        open_ports = []
        total_ports = end_port - start_port + 1
        completed = 0
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self.scan_port, target, port): port 
                for port in range(start_port, end_port + 1)
            }
            
            # Process completed scans
            for future in as_completed(future_to_port):
                completed += 1
                result = future.result()
                
                if result['state'] == 'open':
                    open_ports.append(result)
                
                # Progress indicator
                if not self.verbose and completed % 100 == 0:
                    progress = (completed / total_ports) * 100
                    print(f"[*] Progress: {completed}/{total_ports} ports ({progress:.1f}%)", end='\r')
        
        if not self.verbose:
            print()  # New line after progress
        
        return open_ports
    
    def scan_hosts(self, targets, start_port, end_port):
        """
        Scan multiple hosts
        
        Args:
            targets (list): List of IP addresses or hostnames
            start_port (int): Starting port number
            end_port (int): Ending port number
        
        Returns:
            dict: Dictionary mapping targets to their open ports
        """
        all_results = {}
        
        for target in targets:
            print(f"\n{'='*60}")
            print(f"[*] Scanning target: {target}")
            print(f"{'='*60}")
            
            open_ports = self.scan_range(target, start_port, end_port)
            all_results[target] = open_ports
        
        return all_results
    
    def parse_cidr(self, cidr):
        """
        Parse CIDR notation to get list of IP addresses
        
        Args:
            cidr (str): CIDR notation (e.g., 192.168.1.0/24)
        
        Returns:
            list: List of IP addresses
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            print(f" Invalid CIDR notation: {e}")
            return []
    
    def display_results(self, results, target):
        """
        Display scan results in a formatted way
        
        Args:
            results (list): List of scan results
            target (str): Target that was scanned
        """
        print(f"\n{'='*60}")
        print(f"[+] Scan Results for {target}")
        print(f"{'='*60}")
        print(f"[+] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[+] Found {len(results)} open ports:\n")
        
        if results:
            print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<30}")
            print("-" * 60)
            for result in sorted(results, key=lambda x: x['port']):
                print(f"{result['port']:<10} {result['state']:<10} {result['service']:<30}")
                if result['banner']:
                    print(f"           Banner: {result['banner'][:60]}")
        else:
            print("No open ports found")
    
    def export_json(self, results, filename):
        """
        Export results to JSON file
        
        Args:
            results (dict): Scan results
            filename (str): Output filename
        """
        output = {
            'scan_time': datetime.now().isoformat(),
            'results': results
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n[+] Results exported to {filename}")
    
    def export_csv(self, results, filename):
        """
        Export results to CSV file
        
        Args:
            results (dict): Scan results
            filename (str): Output filename
        """
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Target', 'Port', 'State', 'Service', 'Banner'])
            
            for target, ports in results.items():
                for port_info in ports:
                    writer.writerow([
                        target,
                        port_info['port'],
                        port_info['state'],
                        port_info['service'],
                        port_info['banner']
                    ])
        
        print(f"\n[+] Results exported to {filename}")


def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner for Network Security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        
    )
    
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target IP address, hostname, or CIDR notation (e.g., 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--ports', '-p',
        default='1-1024',
        help='Port range (e.g., 1-1000) or specific ports (e.g., 22,80,443). Default: 1-1024'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=100,
        help='Number of concurrent threads. Default: 100'
    )
    
    parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help='Connection timeout in seconds. Default: 1.0'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file (supports .json and .csv extensions)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Parse target(s)
    targets = []
    if '/' in args.target:
        # CIDR notation
        scanner_temp = PortScanner()
        targets = scanner_temp.parse_cidr(args.target)
        if not targets:
            print("No valid targets found")
            sys.exit(1)
    else:
        targets = [args.target]
    
    # Parse ports
    start_port = 1
    end_port = 65535
    port_list = []
    
    if ',' in args.ports or '-' in args.ports:
        # Parse mixed format: e.g., "22,80,443,1000-2000"
        parts = args.ports.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                # Range like "1000-2000"
                s, e = map(int, part.split('-'))
                port_list.extend(range(s, e + 1))
            else:
                # Single port like "22"
                port_list.append(int(part))
        
        if port_list:
            start_port = min(port_list)
            end_port = max(port_list)
    else:
        # Single port
        start_port = end_port = int(args.ports)
    
    # Create scanner instance
    scanner = PortScanner(
        timeout=args.timeout,
        max_threads=args.threads,
        verbose=args.verbose
    )
    
    # Perform scan
    all_results = {}
    
    try:
        for target in targets:
            try:
                open_ports = scanner.scan_range(target, start_port, end_port)
                all_results[target] = open_ports
                scanner.display_results(open_ports, target)
            except Exception as e:
                print(f"Error scanning {target}: {e}")
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        # Export partial results if output was requested
        if args.output and all_results:
            print(f"[*] Saving partial results to {args.output}...")
            if args.output.endswith('.json'):
                scanner.export_json(all_results, args.output)
            elif args.output.endswith('.csv'):
                scanner.export_csv(all_results, args.output)
        sys.exit(0)
    
    # Export results if requested
    if args.output:
        if args.output.endswith('.json'):
            scanner.export_json(all_results, args.output)
        elif args.output.endswith('.csv'):
            scanner.export_csv(all_results, args.output)
        else:
            print("Unsupported output format. Use .json or .csv")
    
    print("\n[+] All scans complete")


if __name__ == "__main__":
    main()
