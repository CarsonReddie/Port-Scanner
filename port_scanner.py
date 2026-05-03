#!/usr/bin/env python3
"""
Advanced Port Scanner - Cybersecurity Resume Project
Features: TCP Connect, SYN Stealth, UDP scanning, service detection, multi-threading
"""

import argparse
import socket
import threading
import json
import time
import sys
import struct
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field, asdict
import logging

try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    """Data class to store port scan results"""
    port: int
    protocol: str
    state: str
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    latency: float = 0.0
    
    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    """Data class to store complete scan results"""
    target: str
    target_ip: str
    scan_type: str
    timestamp: str
    duration: float
    ports: List[PortResult] = field(default_factory=list)
    
    def to_dict(self):
        return {
            "target": self.target,
            "target_ip": self.target_ip,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "duration": self.duration,
            "ports": [p.to_dict() for p in self.ports]
        }


class ServiceDetector:
    """Service and version detection for open ports"""
    
    COMMON_PORTS = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
        5432: "postgresql", 8080: "http-proxy", 8443: "https-alt",
        139: "netbios-ssn", 135: "msrpc", 587: "smtp-submission",
        993: "imaps", 995: "pop3s", 8081: "http-alt", 8888: "http-alt"
    }
    
    def __init__(self):
        self.socket_timeout = 2.0
    
    def detect_service(self, ip: str, port: int) -> Tuple[str, str, str]:
        """Detect service running on port"""
        service = self.COMMON_PORTS.get(port, "unknown")
        version = ""
        banner = ""
        
        try:
            if service in ["http", "https", "http-proxy", "https-alt"]:
                version, banner = self._probe_http(ip, port, service == "https")
            elif service == "ssh":
                version, banner = self._probe_ssh(ip, port)
            elif service == "ftp":
                version, banner = self._probe_ftp(ip, port)
            elif service in ["smtp", "smtp-submission"]:
                version, banner = self._probe_smtp(ip, port)
            elif service == "mysql":
                version, banner = self._probe_mysql(ip, port)
        except Exception as e:
            logger.debug(f"Service detection failed for {ip}:{port} - {e}")
        
        return service, version, banner
    
    def _probe_http(self, ip: str, port: int, ssl: bool) -> Tuple[str, str]:
        """Probe HTTP/HTTPS service"""
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.socket_timeout)
            raw.connect((ip, port))
            
            if ssl:
                import ssl
                raw = ssl.wrap_socket(raw)
            
            request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: PortScanner/1.0\r\n\r\n"
            raw.send(request.encode())
            
            response = raw.recv(1024).decode('utf-8', errors='ignore')
            raw.close()
            
            version = ""
            banner = response.split('\n')[0] if response else ""
            
            for line in response.split('\n'):
                if 'server:' in line.lower():
                    version = line.split(':', 1)[1].strip()
                    break
            
            return version, banner
        except:
            return "", ""
    
    def _probe_ssh(self, ip: str, port: int) -> Tuple[str, str]:
        """Probe SSH service"""
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.socket_timeout)
            raw.connect((ip, port))
            banner = raw.recv(1024).decode('utf-8', errors='ignore').strip()
            raw.close()
            return banner, banner
        except:
            return "", ""
    
    def _probe_ftp(self, ip: str, port: int) -> Tuple[str, str]:
        """Probe FTP service"""
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.socket_timeout)
            raw.connect((ip, port))
            banner = raw.recv(1024).decode('utf-8', errors='ignore').strip()
            raw.close()
            return banner, banner
        except:
            return "", ""
    
    def _probe_smtp(self, ip: str, port: int) -> Tuple[str, str]:
        """Probe SMTP service"""
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.socket_timeout)
            raw.connect((ip, port))
            banner = raw.recv(1024).decode('utf-8', errors='ignore').strip()
            raw.close()
            return banner, banner
        except:
            return "", ""
    
    def _probe_mysql(self, ip: str, port: int) -> Tuple[str, str]:
        """Probe MySQL service"""
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.socket_timeout)
            raw.connect((ip, port))
            banner = raw.recv(1024).decode('utf-8', errors='ignore').strip()
            raw.close()
            return banner, banner
        except:
            return "", ""


class TCPConnectScanner:
    """TCP Connect Scanner - Full TCP handshake"""
    
    def __init__(self, timeout: float = 1.0, detector: Optional[ServiceDetector] = None):
        self.timeout = timeout
        self.detector = detector or ServiceDetector()
    
    def scan_port(self, ip: str, port: int) -> PortResult:
        """Scan a single TCP port using connect()"""
        start = time.time()
        result = PortResult(port=port, protocol="tcp", state="closed")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            conn_result = sock.connect_ex((ip, port))
            latency = time.time() - start
            
            if conn_result == 0:
                result.state = "open"
                result.latency = latency
                
                service, version, banner = self.detector.detect_service(ip, port)
                result.service = service
                result.version = version
                result.banner = banner[:100] if banner else ""
            
            sock.close()
        except socket.timeout:
            result.state = "filtered"
        except socket.error as e:
            if "refused" in str(e).lower():
                result.state = "closed"
            else:
                result.state = "filtered"
        
        return result


class UDPScanner:
    """UDP Scanner - Sends UDP packets and analyzes responses"""
    
    def __init__(self, timeout: float = 3.0, detector: Optional[ServiceDetector] = None):
        self.timeout = timeout
        self.detector = detector or ServiceDetector()
    
    def scan_port(self, ip: str, port: int) -> PortResult:
        """Scan a single UDP port"""
        start = time.time()
        result = PortResult(port=port, protocol="udp", state="open|filtered")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            if port == 53:
                payload = self._build_dns_query()
            else:
                payload = b"\x00" * 8
            
            sock.sendto(payload, (ip, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                latency = time.time() - start
                result.state = "open"
                result.latency = latency
                result.banner = data[:50].hex() if data else ""
            except socket.timeout:
                pass
            
            sock.close()
        except Exception as e:
            logger.debug(f"UDP scan error {ip}:{port} - {e}")
        
        return result
    
    def _build_dns_query(self) -> bytes:
        """Build a simple DNS query"""
        transaction_id = b'\x12\x34'
        flags = b'\x01\x00'
        qdcount = b'\x00\x01'
        ancount = b'\x00\x00'
        nscount = b'\x00\x00'
        arcount = b'\x00\x00'
        question = b'\x06google\x03com\x00\x00\x01\x00\x01'
        
        return transaction_id + flags + qdcount + ancount + nscount + arcount + question


class SYNStealthScanner:
    """SYN Stealth Scanner - Raw sockets (requires root)"""
    
    def __init__(self, timeout: float = 2.0, detector: Optional[ServiceDetector] = None):
        self.timeout = timeout
        self.detector = detector or ServiceDetector()
        self.source_port = 12345
    
    def scan_port(self, ip: str, port: int) -> PortResult:
        """Scan a single port using SYN stealth scan"""
        if not SCAPY_AVAILABLE:
            return PortResult(port=port, protocol="tcp", state="error", banner="scapy not available")
        
        start = time.time()
        result = PortResult(port=port, protocol="tcp", state="filtered")
        
        try:
            packet = IP(dst=ip)/TCP(sport=self.source_port, dport=port, flags="S")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                latency = time.time() - start
                tcp_layer = response.getlayer(TCP)
                
                if tcp_layer.flags == 0x12:
                    result.state = "open"
                    result.latency = latency
                    service, version, banner = self.detector.detect_service(ip, port)
                    result.service = service
                    result.version = version
                    result.banner = banner[:100] if banner else ""
                    sr1(IP(dst=ip)/TCP(sport=self.source_port, dport=port, flags="R"), 
                        timeout=0.5, verbose=0)
                elif tcp_layer.flags == 0x14:
                    result.state = "closed"
        
        except Exception as e:
            logger.debug(f"SYN scan error {ip}:{port} - {e}")
        
        return result


class PortScanner:
    """Main port scanner orchestrator"""
    
    def __init__(self, 
                 target: str,
                 ports: List[int],
                 scan_type: str = "tcp",
                 threads: int = 100,
                 timeout: float = 1.0,
                 timing: str = "normal"):
        
        self.target = target
        self.target_ip = self._resolve_target(target)
        self.ports = ports
        self.scan_type = scan_type
        self.threads = threads
        self.timeout = timeout
        self.timing = timing
        self.results = ScanResult(
            target=target,
            target_ip=self.target_ip,
            scan_type=scan_type,
            timestamp=datetime.now().isoformat(),
            duration=0.0
        )
        
        self.detector = ServiceDetector()
        
        timing_presets = {
            "paranoid": (5.0, 10),
            "sneaky": (2.0, 25),
            "normal": (1.0, 100),
            "aggressive": (0.5, 300),
            "insane": (0.1, 500)
        }
        
        if timing in timing_presets:
            self.timeout, self.threads = timing_presets[timing]
        
        if scan_type == "syn" and not SCAPY_AVAILABLE:
            print("[!] SYN scan requires scapy. Install with: pip install scapy")
            print("[!] Falling back to TCP connect scan")
            self.scan_type = "tcp"
    
    def _resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[!] Failed to resolve hostname: {target}")
            sys.exit(1)
    
    def scan(self) -> ScanResult:
        """Execute the port scan"""
        print(f"[*] Starting {self.scan_type.upper()} scan of {self.target} ({self.target_ip})")
        print(f"[*] Scanning {len(self.ports)} ports with {self.threads} threads")
        print(f"[*] Timeout: {self.timeout}s | Timing: {self.timing}")
        print("-" * 60)
        
        start_time = time.time()
        
        if self.scan_type == "tcp":
            scanner = TCPConnectScanner(self.timeout, self.detector)
            scan_func = scanner.scan_port
        elif self.scan_type == "syn":
            scanner = SYNStealthScanner(self.timeout, self.detector)
            scan_func = scanner.scan_port
        elif self.scan_type == "udp":
            scanner = UDPScanner(self.timeout, self.detector)
            scan_func = scanner.scan_port
        else:
            raise ValueError(f"Unknown scan type: {self.scan_type}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(scan_func, self.target_ip, port): port 
                for port in self.ports
            }
            
            completed = 0
            total = len(self.ports)
            
            for future in as_completed(future_to_port):
                completed += 1
                if completed % 50 == 0 or completed == total:
                    print(f"\r[*] Progress: {completed}/{total} ports scanned", end="", flush=True)
                
                try:
                    result = future.result()
                    if result.state in ["open", "open|filtered"]:
                        self.results.ports.append(result)
                        print(f"\n[+] {result.protocol.upper()}:{result.port:5d} {result.state:15s} {result.service:15s} {result.version}")
                except Exception as e:
                    logger.error(f"Error scanning port: {e}")
        
        print(f"\r[*] Progress: {total}/{total} ports scanned")
        self.results.duration = time.time() - start_time
        print("-" * 60)
        print(f"[*] Scan completed in {self.results.duration:.2f} seconds")
        print(f"[*] Found {len(self.results.ports)} open port(s)")
        
        return self.results
    
    def print_results(self):
        """Print formatted scan results"""
        print("\n" + "=" * 70)
        print(f"SCAN REPORT FOR {self.target} ({self.target_ip})")
        print("=" * 70)
        print(f"Scan Type: {self.scan_type.upper()}")
        print(f"Timestamp: {self.results.timestamp}")
        print(f"Duration:  {self.results.duration:.2f}s")
        print("-" * 70)
        print(f"{'PORT':<12} {'STATE':<15} {'SERVICE':<15} {'VERSION':<20}")
        print("-" * 70)
        
        for port in sorted(self.results.ports, key=lambda x: x.port):
            print(f"{port.protocol.upper()}:{port.port:<5} {port.state:<15} {port.service:<15} {port.version:<20}")
        
        print("=" * 70)
    
    def save_results(self, filename: str, fmt: str = "json"):
        """Save results to file"""
        if fmt == "json":
            with open(filename, 'w') as f:
                json.dump(self.results.to_dict(), f, indent=2)
        elif fmt == "txt":
            with open(filename, 'w') as f:
                f.write(f"Scan Report for {self.target} ({self.target_ip})\n")
                f.write(f"Scan Type: {self.scan_type.upper()}\n")
                f.write(f"Timestamp: {self.results.timestamp}\n")
                f.write(f"Duration: {self.results.duration:.2f}s\n")
                f.write("-" * 70 + "\n")
                f.write(f"{'PORT':<12} {'STATE':<15} {'SERVICE':<15} {'VERSION':<20}\n")
                f.write("-" * 70 + "\n")
                for port in sorted(self.results.ports, key=lambda x: x.port):
                    f.write(f"{port.protocol.upper()}:{port.port:<5} {port.state:<15} {port.service:<15} {port.version:<20}\n")
        print(f"[*] Results saved to {filename}")


def parse_ports(port_str: str) -> List[int]:
    """Parse port specification string"""
    ports = set()
    
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    
    return sorted(ports)


def get_top_ports(n: int = 100) -> List[int]:
    """Get top N most common ports"""
    common = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
        8443, 8888, 27017, 49665, 49666, 49667, 49668, 49669, 49670
    ]
    return common[:n]


def main():
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner - Cybersecurity Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1
  %(prog)s scanme.nmap.org -p 1-1000 -t 200
  %(prog)s 10.0.0.1 -p 22,80,443 --scan-type syn --timing aggressive
  %(prog)s target.com -p- --output results.json --format json
        """
    )
    
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1000", 
                        help="Port specification (e.g., '22,80,443' or '1-1000' or '-' for all)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--scan-type", choices=["tcp", "syn", "udp"], default="tcp",
                        help="Scan type: tcp (connect), syn (stealth), udp (default: tcp)")
    parser.add_argument("--timing", choices=["paranoid", "sneaky", "normal", "aggressive", "insane"],
                        default="normal", help="Timing template (default: normal)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["json", "txt"], default="json",
                        help="Output format (default: json)")
    parser.add_argument("--top-ports", type=int, help="Scan top N most common ports")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.scan_type == "syn" and os.geteuid() != 0:
        print("[!] SYN scan requires root privileges. Run with sudo.")
        sys.exit(1)
    
    if args.top_ports:
        ports = get_top_ports(args.top_ports)
    elif args.ports == "-":
        ports = list(range(1, 65536))
    else:
        ports = parse_ports(args.ports)
    
    scanner = PortScanner(
        target=args.target,
        ports=ports,
        scan_type=args.scan_type,
        threads=args.threads,
        timeout=args.timeout,
        timing=args.timing
    )
    
    try:
        results = scanner.scan()
        scanner.print_results()
        
        if args.output:
            scanner.save_results(args.output, args.format)
        
        if len(results.ports) == 0:
            print("\n[*] No open ports found. Try adjusting timeout or scan type.")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
