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
    os_info: Dict[str, any] = field(default_factory=dict)
    discovered_hosts: List[Dict[str, str]] = field(default_factory=list)
    
    def to_dict(self):
        return {
            "target": self.target,
            "target_ip": self.target_ip,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "duration": self.duration,
            "os_info": self.os_info,
            "ports": [p.to_dict() for p in self.ports],
            "discovered_hosts": self.discovered_hosts
        }


def print_scan_results(results: ScanResult):
    """Print formatted scan results"""
    print("\n" + "=" * 70)
    print(f"SCAN REPORT FOR {results.target} ({results.target_ip})")
    print("=" * 70)
    print(f"Scan Type: {results.scan_type.upper()}")
    print(f"Timestamp: {results.timestamp}")
    print(f"Duration:  {results.duration:.2f}s")
    
    if results.os_info and results.os_info.get('name', 'unknown') != 'unknown':
        print(f"OS Detection: {results.os_info['name']} (Accuracy: {results.os_info.get('accuracy', 0)}%)")
        if results.os_info.get('ttl'):
            print(f"  TTL: {results.os_info['ttl']}, Window: {results.os_info.get('window_size', 'N/A')}")
    
    print("-" * 70)
    
    if results.discovered_hosts:
        print(f"\nDISCOVERED HOSTS ({len(results.discovered_hosts)} found):")
        print(f"{'IP':<20} {'MAC':<20} {'STATUS':<10}")
        print("-" * 50)
        for host in results.discovered_hosts:
            print(f"{host['ip']:<20} {host.get('mac', 'N/A'):<20} {host['status']:<10}")
        print("=" * 70)
    
    if results.ports:
        print(f"\n{'PORT':<12} {'STATE':<15} {'SERVICE':<15} {'VERSION':<20}")
        print("-" * 70)
        for port in sorted(results.ports, key=lambda x: x.port):
            print(f"{port.protocol.upper()}:{port.port:<5} {port.state:<15} {port.service:<15} {port.version:<20}")
    else:
        print("\nNo open ports found.")
    
    print("=" * 70)


def save_scan_results(results: ScanResult, filename: str, fmt: str = "json"):
    """Save scan results to file"""
    if fmt == "json":
        with open(filename, 'w') as f:
            json.dump(results.to_dict(), f, indent=2)
    elif fmt == "txt":
        with open(filename, 'w') as f:
            f.write(f"Scan Report for {results.target} ({results.target_ip})\n")
            f.write(f"Scan Type: {results.scan_type.upper()}\n")
            f.write(f"Timestamp: {results.timestamp}\n")
            f.write(f"Duration: {results.duration:.2f}s\n")
            f.write("-" * 70 + "\n")
            f.write(f"{'PORT':<12} {'STATE':<15} {'SERVICE':<15} {'VERSION':<20}\n")
            f.write("-" * 70 + "\n")
            for port in sorted(results.ports, key=lambda x: x.port):
                f.write(f"{port.protocol.upper()}:{port.port:<5} {port.state:<15} {port.service:<15} {port.version:<20}\n")
    print(f"[*] Results saved to {filename}")


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


class OSDetector:
    """OS Detection using TTL, TCP window size, and TCP options fingerprinting"""
    
    TTL_SIGNATURES = {
        64: ["Linux", "macOS", "Android"],
        128: ["Windows"],
        255: ["Cisco IOS", "Solaris"],
        32: ["Windows 95/98/ME"],
        60: ["AIX"],
    }
    
    WINDOW_SIZE_SIGNATURES = {
        65535: ["Linux (2.4.x)", "FreeBSD"],
        5840: ["Linux (2.6.x)"],
        8192: ["Windows", "macOS"],
        16384: ["AIX"],
        4128: ["Cisco IOS"],
    }
    
    def __init__(self):
        self.os_info = {
            "name": "unknown",
            "accuracy": 0,
            "ttl": None,
            "window_size": None,
            "tcp_options": None
        }
    
    def detect_os(self, ip: str, open_port: int = None) -> Dict[str, any]:
        """Detect OS using passive fingerprinting techniques"""
        if SCAPY_AVAILABLE:
            return self._detect_os_active(ip, open_port)
        # Without scapy, try to detect OS from service banners
        return self._detect_os_passive(ip, open_port)
    
    def _detect_os_passive(self, ip: str, open_port: int = None) -> Dict[str, any]:
        """Passive OS detection using service banners"""
        # Try to grab banners from common ports
        test_ports = [open_port] if open_port else [22, 80, 443, 3389]
        os_hints = []

        for port in test_ports:
            if port is None:
                continue
            try:
                if port == 22:  # SSH
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    sock.connect((ip, port))
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    sock.close()

                    # Analyze SSH banner for OS hints
                    if 'ubuntu' in banner.lower():
                        os_hints.append('Linux (Ubuntu)')
                        self.os_info['name'] = 'Linux (Ubuntu)'
                        self.os_info['accuracy'] = 80
                    elif 'debian' in banner.lower():
                        os_hints.append('Linux (Debian)')
                        self.os_info['name'] = 'Linux (Debian)'
                        self.os_info['accuracy'] = 80
                    elif 'centos' in banner.lower():
                        os_hints.append('Linux (CentOS)')
                        self.os_info['name'] = 'Linux (CentOS)'
                        self.os_info['accuracy'] = 80
                    elif 'windows' in banner.lower():
                        os_hints.append('Windows')
                        self.os_info['name'] = 'Windows'
                        self.os_info['accuracy'] = 80

                elif port in [80, 443]:  # HTTP/HTTPS
                    import ssl
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    if port == 443:
                        sock = ssl.wrap_socket(sock)
                    sock.connect((ip, port))
                    sock.send(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    sock.close()

                    # Check Server header
                    for line in response.split('\n'):
                        if 'server:' in line.lower():
                            server = line.split(':', 1)[1].strip()
                            if 'ubuntu' in server.lower() or 'debian' in server.lower():
                                os_hints.append('Linux')
                                self.os_info['name'] = 'Linux'
                                self.os_info['accuracy'] = 60
                            elif 'windows' in server.lower():
                                os_hints.append('Windows')
                                self.os_info['name'] = 'Windows'
                                self.os_info['accuracy'] = 60

            except:
                continue

        return self.os_info
    
    def _detect_os_active(self, ip: str, open_port: int = None) -> Dict[str, any]:
        """Active OS detection using SYN probe and response analysis"""
        try:
            # Use open port if available, otherwise try common ports
            test_ports = [open_port] if open_port else [22, 80, 443, 3389, 22]
            response = None
            used_port = None
            
            for port in test_ports:
                if port is None:
                    continue
                packet = IP(dst=ip)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=2, verbose=0)
                if response:
                    used_port = port
                    break
            
            if response and response.haslayer(IP) and response.haslayer(TCP):
                ip_layer = response.getlayer(IP)
                tcp_layer = response.getlayer(TCP)
                
                ttl = ip_layer.ttl
                window_size = tcp_layer.window
                tcp_options = tcp_layer.options
                
                self.os_info["ttl"] = ttl
                self.os_info["window_size"] = window_size
                self.os_info["tcp_options"] = str(tcp_options)
                
                os_matches = []
                
                if ttl in self.TTL_SIGNATURES:
                    os_matches.extend(self.TTL_SIGNATURES[ttl])
                
                if window_size in self.WINDOW_SIZE_SIGNATURES:
                    os_matches.extend(self.WINDOW_SIZE_SIGNATURES[window_size])
                
                if os_matches:
                    from collections import Counter
                    most_common = Counter(os_matches).most_common(1)
                    if most_common:
                        self.os_info["name"] = most_common[0][0]
                        self.os_info["accuracy"] = min(90, 40 + most_common[0][1] * 20)
                
                # Send RST to close using the port we got response from
                if used_port:
                    sr1(IP(dst=ip)/TCP(dport=used_port, flags="R"), timeout=0.5, verbose=0)
        
        except Exception as e:
            logger.debug(f"OS detection error for {ip}: {e}")
        
        return self.os_info


class NullScan:
    """NULL Scan - Send TCP packet with no flags (stealth/evasion)"""
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    
    def scan_port(self, ip: str, port: int) -> PortResult:
        """Scan port using NULL scan technique"""
        if not SCAPY_AVAILABLE:
            return PortResult(port=port, protocol="tcp", state="error", banner="scapy not available")
        
        start = time.time()
        result = PortResult(port=port, protocol="tcp", state="open|filtered")
        
        try:
            packet = IP(dst=ip)/TCP(dport=port, flags=0)
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x14:  # RST-ACK
                    result.state = "closed"
            elif response and response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
                    result.state = "filtered"
            
            result.latency = time.time() - start
        
        except Exception as e:
            logger.debug(f"NULL scan error {ip}:{port} - {e}")
        
        return result


class FinScan:
    """FIN Scan - Send TCP packet with FIN flag (stealth/evasion)"""
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    
    def scan_port(self, ip: str, port: int) -> PortResult:
        """Scan port using FIN scan technique"""
        if not SCAPY_AVAILABLE:
            return PortResult(port=port, protocol="tcp", state="error", banner="scapy not available")
        
        start = time.time()
        result = PortResult(port=port, protocol="tcp", state="open|filtered")
        
        try:
            packet = IP(dst=ip)/TCP(dport=port, flags="F")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x14:  # RST-ACK
                    result.state = "closed"
            elif response and response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
                    result.state = "filtered"
            
            result.latency = time.time() - start
        
        except Exception as e:
            logger.debug(f"FIN scan error {ip}:{port} - {e}")
        
        return result


class XmasScan:
    """Xmas Scan - Send TCP packet with FIN, URG, PSH flags (stealth/evasion)"""
    
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
    
    def scan_port(self, ip: str, port: int) -> PortResult:
        """Scan port using Xmas scan technique"""
        if not SCAPY_AVAILABLE:
            return PortResult(port=port, protocol="tcp", state="error", banner="scapy not available")
        
        start = time.time()
        result = PortResult(port=port, protocol="tcp", state="open|filtered")
        
        try:
            packet = IP(dst=ip)/TCP(dport=port, flags="FPU")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x14:  # RST-ACK
                    result.state = "closed"
            elif response and response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer.type == 3 and icmp_layer.code in [1, 2, 3, 9, 10, 13]:
                    result.state = "filtered"
            
            result.latency = time.time() - start
        
        except Exception as e:
            logger.debug(f"Xmas scan error {ip}:{port} - {e}")
        
        return result


class HostDiscovery:
    """Host discovery using ping sweep and ARP scan for local networks"""
    
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
    
    def discover_hosts(self, network: str) -> List[Dict[str, str]]:
        """Discover live hosts using ping sweep"""
        hosts = []
        
        try:
            ip = network.split('/')[0]
            cidr = int(network.split('/')[1]) if '/' in network else 24
            
            if cidr < 24:
                print(f"[*] CIDR /{cidr} is large, limiting to first 256 addresses")
                cidr = 24
            
            base_ip = '.'.join(ip.split('.')[:3])
            start = 1
            end = 255
            
            print(f"[*] Ping sweep on {base_ip}.0/{cidr}")
            
            if SCAPY_AVAILABLE:
                hosts = self._arp_sweep(network) if self._is_local_network(ip) else self._icmp_sweep(base_ip, start, end)
            else:
                hosts = self._icmp_sweep(base_ip, start, end)
        
        except Exception as e:
            logger.error(f"Host discovery error: {e}")
        
        return hosts
    
    def _is_local_network(self, ip: str) -> bool:
        """Check if IP is in local network range"""
        local_ranges = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                       "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                       "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."]
        return any(ip.startswith(prefix) for prefix in local_ranges)
    
    def _arp_sweep(self, network: str) -> List[Dict[str, str]]:
        """ARP scan for local network discovery"""
        hosts = []
        base_ip = network.split('/')[0]
        base = '.'.join(base_ip.split('.')[:3])
        
        print(f"[*] ARP sweep on {base}.0/24")
        
        for i in range(1, 255):
            target = f"{base}.{i}"
            try:
                packet = IP(dst=target)/TCP(dport=80, flags="S")
                response = sr1(packet, timeout=self.timeout, verbose=0)
                if response:
                    mac = response.src if hasattr(response, 'src') else "unknown"
                    hosts.append({"ip": target, "mac": mac, "status": "up"})
                    print(f"[+] Host discovered: {target} ({mac})")
            except:
                pass
        
        return hosts
    
    def _icmp_sweep(self, base_ip: str, start: int, end: int) -> List[Dict[str, str]]:
        """ICMP ping sweep for host discovery"""
        hosts = []
        
        if SCAPY_AVAILABLE:
            for i in range(start, end + 1):
                target = f"{base_ip}.{i}"
                try:
                    packet = IP(dst=target)/ICMP()
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                    if response:
                        hosts.append({"ip": target, "mac": "N/A", "status": "up"})
                        print(f"[+] Host discovered: {target}")
                except:
                    pass
        else:
            for i in range(start, end + 1):
                target = f"{base_ip}.{i}"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    sock.settimeout(self.timeout)
                    sock.sendto(b'\x08\x00\x00\x00\x00\x00\x00\x00', (target, 0))
                    try:
                        data, addr = sock.recvfrom(1024)
                        hosts.append({"ip": target, "mac": "N/A", "status": "up"})
                        print(f"[+] Host discovered: {target}")
                    except socket.timeout:
                        pass
                    sock.close()
                except:
                    pass
        
        return hosts


def parse_cidr(cidr: str) -> List[str]:
    """Parse CIDR notation and return list of IPs"""
    import ipaddress
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        print(f"[!] Invalid CIDR notation: {e}")
        return []


class PortScanner:
    """Main port scanner orchestrator"""
    
    def __init__(self,
                 target: str,
                 ports: List[int],
                 scan_type: str = "tcp",
                 threads: int = 100,
                 timeout: float = 1.0,
                 timing: str = "normal",
                 os_detection: bool = False,
                 discover_hosts: bool = False):
        
        self.target = target
        self.target_ip = self._resolve_target(target)
        self.ports = ports
        self.scan_type = scan_type
        self.threads = threads
        self.timeout = timeout
        self.timing = timing
        self.os_detection = os_detection
        self.discover_hosts = discover_hosts
        self.results = ScanResult(
            target=target,
            target_ip=self.target_ip,
            scan_type=scan_type,
            timestamp=datetime.now().isoformat(),
            duration=0.0
        )
        
        self.detector = ServiceDetector()
        self.os_detector = OSDetector()
        
        timing_presets = {
            "paranoid": (5.0, 10),
            "sneaky": (2.0, 25),
            "normal": (1.0, 100),
            "aggressive": (0.5, 300),
            "insane": (0.1, 500)
        }
        
        if timing in timing_presets:
            self.timeout, self.threads = timing_presets[timing]
        
        if scan_type in ["syn", "null", "fin", "xmas"] and not SCAPY_AVAILABLE:
            print("[!] Stealth scans require scapy. Install with: pip install scapy")
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
        """Execute the port scan with optional OS detection and host discovery"""
        print(f"[*] Starting {self.scan_type.upper()} scan of {self.target} ({self.target_ip})")
        
        if self.discover_hosts:
            print(f"[*] Performing host discovery...")
            discovery = HostDiscovery(self.timeout)
            if '/' in self.target:
                hosts = discovery.discover_hosts(self.target)
            else:
                hosts = discovery.discover_hosts(f"{self.target}/24")
            self.results.discovered_hosts = hosts
            print(f"[*] Found {len(hosts)} live host(s)")
        
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
        elif self.scan_type == "null":
            scanner = NullScan(self.timeout)
            scan_func = scanner.scan_port
        elif self.scan_type == "fin":
            scanner = FinScan(self.timeout)
            scan_func = scanner.scan_port
        elif self.scan_type == "xmas":
            scanner = XmasScan(self.timeout)
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
        
        if self.os_detection:
            print("[*] Performing OS detection...")
            # Get an open port to use for OS detection
            open_port = None
            if self.results.ports:
                open_port = self.results.ports[0].port
            self.results.os_info = self.os_detector.detect_os(self.target_ip, open_port)
            print(f"[*] OS Detection: {self.results.os_info.get('name', 'unknown')} (Accuracy: {self.results.os_info.get('accuracy', 0)}%)")
        
        return self.results
    
    def print_results(self):
        """Print formatted scan results"""
        print_scan_results(self.results)
    
    def save_results(self, filename: str, fmt: str = "json"):
        """Save results to file"""
        save_scan_results(self.results, filename, fmt)


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


class InteractiveShell:
    """Interactive shell for the port scanner"""
    
    def __init__(self):
        self.target = None
        self.ports = list(range(1, 1001))
        self.scan_type = "tcp"
        self.threads = 100
        self.timeout = 1.0
        self.timing = "normal"
        self.output = None
        self.format = "json"
        self.os_detection = False
        self.discover_hosts = False
        self.results = None
        self.running = True
        
        print("\n" + "=" * 60)
        print("   PORT SCANNER INTERACTIVE SHELL")
        print("=" * 60)
        print("Type 'help' for available commands, 'exit' to quit")
        print("=" * 60 + "\n")
    
    def cmd_help(self, args=None):
        """Show available commands"""
        print("\nAvailable Commands:")
        print("-" * 50)
        print("  help                      - Show this help message")
        print("  set target <host>         - Set target IP or hostname")
        print("  set ports <ports>         - Set ports (e.g., '22,80,443' or '1-1000')")
        print("  set type <tcp|syn|udp|null|fin|xmas> - Set scan type")
        print("  set threads <n>           - Set number of threads")
        print("  set timeout <secs>        - Set socket timeout")
        print("  set timing <preset>       - Set timing (paranoid/sneaky/normal/aggressive/insane)")
        print("  set output <file>         - Set output file")
        print("  set format <json|txt>     - Set output format")
        print("  set os-detection <on|off> - Enable/disable OS detection")
        print("  set discover <on|off>     - Enable/disable host discovery")
        print("  show                      - Show current settings")
        print("  scan                      - Start the port scan")
        print("  results                   - Show scan results")
        print("  save                      - Save results to file")
        print("  clear                     - Clear screen")
        print("  exit/quit                 - Exit the shell")
        print("-" * 50 + "\n")
    
    def cmd_set(self, args):
        """Set configuration options"""
        if not args:
            print("[!] Usage: set <option> <value>")
            return
        
        parts = args.split(None, 1)
        if len(parts) < 2:
            print("[!] Usage: set <option> <value>")
            return
        
        option, value = parts[0].lower(), parts[1]
        
        if option == "target":
            self.target = value
            print(f"[*] Target set to: {self.target}")
        elif option == "ports":
            if value == "-":
                self.ports = list(range(1, 65536))
            else:
                self.ports = parse_ports(value)
            print(f"[*] Ports set to: {len(self.ports)} ports")
        elif option == "type":
            if value in ["tcp", "syn", "udp", "null", "fin", "xmas"]:
                self.scan_type = value
                print(f"[*] Scan type set to: {self.scan_type}")
            else:
                print("[!] Invalid scan type. Use: tcp, syn, udp, null, fin, xmas")
        elif option == "threads":
            try:
                self.threads = int(value)
                print(f"[*] Threads set to: {self.threads}")
            except ValueError:
                print("[!] Invalid number of threads")
        elif option == "timeout":
            try:
                self.timeout = float(value)
                print(f"[*] Timeout set to: {self.timeout}s")
            except ValueError:
                print("[!] Invalid timeout value")
        elif option == "timing":
            if value in ["paranoid", "sneaky", "normal", "aggressive", "insane"]:
                self.timing = value
                print(f"[*] Timing set to: {self.timing}")
            else:
                print("[!] Invalid timing. Use: paranoid, sneaky, normal, aggressive, insane")
        elif option == "output":
            self.output = value
            print(f"[*] Output file set to: {self.output}")
        elif option == "format":
            if value in ["json", "txt"]:
                self.format = value
                print(f"[*] Output format set to: {self.format}")
            else:
                print("[!] Invalid format. Use: json, txt")
        elif option == "os-detection":
            self.os_detection = value.lower() in ["true", "yes", "1", "on"]
            print(f"[*] OS detection set to: {self.os_detection}")
        elif option == "discover":
            self.discover_hosts = value.lower() in ["true", "yes", "1", "on"]
            print(f"[*] Host discovery set to: {self.discover_hosts}")
        else:
            print(f"[!] Unknown option: {option}")
    
    def cmd_show(self, args=None):
        """Show current settings"""
        print("\nCurrent Settings:")
        print("-" * 40)
        print(f"  Target:    {self.target or '(not set)'}")
        print(f"  Ports:     {len(self.ports)} ports")
        print(f"  Scan Type: {self.scan_type}")
        print(f"  Threads:   {self.threads}")
        print(f"  Timeout:   {self.timeout}s")
        print(f"  Timing:    {self.timing}")
        print(f"  Output:    {self.output or '(not set)'}")
        print(f"  Format:    {self.format}")
        print(f"  OS Detect: {self.os_detection}")
        print(f"  Discover:  {self.discover_hosts}")
        print("-" * 40 + "\n")
    
    def cmd_scan(self, args=None):
        """Execute port scan"""
        if not self.target:
            print("[!] No target set. Use 'set target <host>' first.")
            return
        
        if self.scan_type in ["syn", "null", "fin", "xmas"] and os.geteuid() != 0:
            print(f"[!] {self.scan_type.upper()} scan requires root privileges. Run with sudo.")
            return
        
        scanner = PortScanner(
            target=self.target,
            ports=self.ports,
            scan_type=self.scan_type,
            threads=self.threads,
            timeout=self.timeout,
            timing=self.timing,
            os_detection=self.os_detection,
            discover_hosts=self.discover_hosts
        )
        
        try:
            self.results = scanner.scan()
            print_scan_results(self.results)
            
            if self.output:
                save_scan_results(self.results, self.output, self.format)
        
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        except Exception as e:
            print(f"\n[!] Error: {e}")
    
    def cmd_results(self, args=None):
        """Show scan results"""
        if not self.results:
            print("[!] No scan results available. Run 'scan' first.")
            return
        print_scan_results(self.results)
    
    def cmd_save(self, args=None):
        """Save results to file"""
        if not self.results:
            print("[!] No scan results available. Run 'scan' first.")
            return
        
        output = self.output
        if args:
            output = args
        
        if not output:
            print("[!] No output file set. Use 'set output <file>' or 'save <filename>'")
            return
        
        save_scan_results(self.results, output, self.format)
    
    def cmd_clear(self, args=None):
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def cmd_exit(self, args=None):
        """Exit the shell"""
        print("[*] Goodbye!")
        self.running = False
    
    def run(self):
        """Run the interactive shell"""
        while self.running:
            try:
                prompt = f"pscanner> " if not self.target else f"pscanner ({self.target})> "
                cmdline = input(prompt).strip()
                
                if not cmdline:
                    continue
                
                parts = cmdline.split(None, 1)
                cmd = parts[0].lower()
                args = parts[1] if len(parts) > 1 else None
                
                if cmd in ["exit", "quit"]:
                    self.cmd_exit()
                elif cmd == "help":
                    self.cmd_help()
                elif cmd == "set":
                    self.cmd_set(args)
                elif cmd == "show":
                    self.cmd_show()
                elif cmd == "scan":
                    self.cmd_scan()
                elif cmd == "results":
                    self.cmd_results()
                elif cmd == "save":
                    self.cmd_save(args)
                elif cmd == "clear":
                    self.cmd_clear()
                else:
                    print(f"[!] Unknown command: {cmd}. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\n[*] Use 'exit' or 'quit' to leave the shell")
            except EOFError:
                print("\n[*] Goodbye!")
                break


class SimpleGUI:
    """Simple GUI for the port scanner using tkinter"""
    
    def __init__(self):
        try:
            import tkinter as tk
            from tkinter import ttk, scrolledtext, messagebox
            self.tk = tk
            self.ttk = ttk
            self.scrolledtext = scrolledtext
            self.messagebox = messagebox
            self.available = True
        except ImportError:
            self.available = False
            return
        
        self.root = tk.Tk()
        self.root.title("Port Scanner - Cybersecurity Tool")
        self.root.geometry("900x700")
        
        self.target_var = tk.StringVar()
        self.ports_var = tk.StringVar(value="1-1000")
        self.scan_type_var = tk.StringVar(value="tcp")
        self.threads_var = tk.StringVar(value="100")
        self.timing_var = tk.StringVar(value="normal")
        self.output_var = tk.StringVar()
        
        self.results = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the GUI components"""
        main_frame = self.ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(self.tk.N, self.tk.W, self.tk.E, self.tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        row = 0
        self.ttk.Label(main_frame, text="Target (IP/Hostname):").grid(row=row, column=0, sticky=self.tk.W, pady=5)
        self.ttk.Entry(main_frame, textvariable=self.target_var, width=40).grid(row=row, column=1, sticky=(self.tk.W, self.tk.E), pady=5)
        self.ttk.Button(main_frame, text="Scan", command=self.start_scan).grid(row=row, column=2, padx=5, pady=5)
        
        row += 1
        self.ttk.Label(main_frame, text="Ports:").grid(row=row, column=0, sticky=self.tk.W, pady=5)
        self.ttk.Entry(main_frame, textvariable=self.ports_var, width=40).grid(row=row, column=1, sticky=(self.tk.W, self.tk.E), pady=5)
        self.ttk.Label(main_frame, text="(e.g., '22,80,443' or '1-1000')").grid(row=row, column=2, padx=5, pady=5, sticky=self.tk.W)
        
        row += 1
        self.ttk.Label(main_frame, text="Scan Type:").grid(row=row, column=0, sticky=self.tk.W, pady=5)
        types = [("TCP Connect", "tcp"), ("SYN Stealth (root)", "syn"), ("UDP", "udp"), ("NULL (root)", "null"), ("FIN (root)", "fin"), ("Xmas (root)", "xmas")]
        for i, (text, val) in enumerate(types):
            self.ttk.Radiobutton(main_frame, text=text, variable=self.scan_type_var, value=val).grid(
                row=row, column=1+i, sticky=self.tk.W, pady=5)
        
        row += 1
        self.ttk.Label(main_frame, text="Threads:").grid(row=row, column=0, sticky=self.tk.W, pady=5)
        self.ttk.Scale(main_frame, from_=1, to=500, variable=self.threads_var, orient=self.tk.HORIZONTAL).grid(
            row=row, column=1, sticky=(self.tk.W, self.tk.E), pady=5)
        self.tk.Label(main_frame, textvariable=self.threads_var).grid(row=row, column=2, pady=5)
        
        row += 1
        self.ttk.Label(main_frame, text="Timing:").grid(row=row, column=0, sticky=self.tk.W, pady=5)
        timings = ["paranoid", "sneaky", "normal", "aggressive", "insane"]
        self.ttk.Combobox(main_frame, textvariable=self.timing_var, values=timings, state="readonly").grid(
            row=row, column=1, sticky=(self.tk.W, self.tk.E), pady=5)
        
        row += 1
        self.ttk.Label(main_frame, text="Output File:").grid(row=row, column=0, sticky=self.tk.W, pady=5)
        self.ttk.Entry(main_frame, textvariable=self.output_var, width=40).grid(row=row, column=1, sticky=(self.tk.W, self.tk.E), pady=5)
        self.ttk.Button(main_frame, text="Save Results", command=self.save_results).grid(row=row, column=2, padx=5, pady=5)
        
        row += 1
        self.output_text = self.scrolledtext.ScrolledText(main_frame, width=100, height=30)
        self.output_text.grid(row=row, column=0, columnspan=3, pady=10, sticky=(self.tk.W, self.tk.E, self.tk.N, self.tk.S))
        
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(row, weight=1)
    
    def start_scan(self):
        """Start the port scan in a separate thread"""
        target = self.target_var.get().strip()
        if not target:
            self.messagebox.showerror("Error", "Please enter a target IP or hostname")
            return
        
        ports_str = self.ports_var.get().strip()
        if ports_str == "-":
            ports = list(range(1, 65536))
        else:
            ports = parse_ports(ports_str)
        
        scan_type = self.scan_type_var.get()
        threads = int(self.threads_var.get())
        timing = self.timing_var.get()
        
        if scan_type in ["syn", "null", "fin", "xmas"] and os.geteuid() != 0:
            self.messagebox.showerror("Error", f"{scan_type.upper()} scan requires root privileges")
            return
        
        self.output_text.delete(1.0, self.tk.END)
        self.output_text.insert(self.tk.END, f"[*] Starting {scan_type.upper()} scan of {target}\n")
        self.output_text.update()
        
        import threading
        thread = threading.Thread(target=self._run_scan, args=(target, ports, scan_type, threads, timing))
        thread.daemon = True
        thread.start()
    
    def _run_scan(self, target, ports, scan_type, threads, timing):
        """Run the scan in background"""
        try:
            scanner = PortScanner(
                target=target,
                ports=ports,
                scan_type=scan_type,
                threads=threads,
                timing=timing
            )
            
            self.output_text.insert(self.tk.END, f"[*] Scanning {len(ports)} ports with {threads} threads\n")
            self.output_text.update()
            
            results = scanner.scan()
            self.results = results
            
            self.output_text.insert(self.tk.END, "\n" + "=" * 70 + "\n")
            self.output_text.insert(self.tk.END, f"SCAN REPORT FOR {results.target} ({results.target_ip})\n")
            self.output_text.insert(self.tk.END, "=" * 70 + "\n")
            self.output_text.insert(self.tk.END, f"Scan Type: {results.scan_type.upper()}\n")
            self.output_text.insert(self.tk.END, f"Duration:  {results.duration:.2f}s\n")
            self.output_text.insert(self.tk.END, "-" * 70 + "\n")
            self.output_text.insert(self.tk.END, f"{'PORT':<12} {'STATE':<15} {'SERVICE':<15} {'VERSION':<20}\n")
            self.output_text.insert(self.tk.END, "-" * 70 + "\n")
            
            for port in sorted(results.ports, key=lambda x: x.port):
                self.output_text.insert(self.tk.END,
                    f"{port.protocol.upper()}:{port.port:<5} {port.state:<15} {port.service:<15} {port.version:<20}\n")
            
            self.output_text.insert(self.tk.END, "=" * 70 + "\n")
            self.output_text.insert(self.tk.END, f"\n[*] Found {len(results.ports)} open port(s)\n")
        
        except Exception as e:
            self.output_text.insert(self.tk.END, f"\n[!] Error: {e}\n")
    
    def save_results(self):
        """Save scan results to file"""
        if not self.results:
            self.messagebox.showwarning("Warning", "No scan results to save. Run a scan first.")
            return
        
        output = self.output_var.get().strip()
        if not output:
            self.messagebox.showwarning("Warning", "Please enter an output filename")
            return
        
        save_scan_results(self.results, output, "json")
        self.messagebox.showinfo("Success", f"Results saved to {output}")
    
    def run(self):
        """Run the GUI main loop"""
        if self.available:
            self.root.mainloop()


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
  %(prog)s 192.168.1.0/24 --discover-hosts
  %(prog)s target.com --os-detection -p 1-1000

Interactive Mode:
  %(prog)s --interactive
  %(prog)s -i

GUI Mode:
  %(prog)s --gui
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target IP address, hostname, or CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1000",
                        help="Port specification (e.g., '22,80,443' or '1-1000' or '-' for all)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--scan-type", choices=["tcp", "syn", "udp", "null", "fin", "xmas"],
                        default="tcp", help="Scan type: tcp, syn, udp, null, fin, xmas (default: tcp)")
    parser.add_argument("--timing", choices=["paranoid", "sneaky", "normal", "aggressive", "insane"],
                        default="normal", help="Timing template (default: normal)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["json", "txt"], default="json",
                        help="Output format (default: json)")
    parser.add_argument("--top-ports", type=int, help="Scan top N most common ports")
    parser.add_argument("--os-detection", action="store_true", help="Enable OS detection")
    parser.add_argument("--discover-hosts", action="store_true", help="Discover live hosts (CIDR required)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive shell mode")
    parser.add_argument("--gui", action="store_true", help="Run with GUI")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.interactive:
        shell = InteractiveShell()
        shell.run()
        return
    
    if args.gui:
        gui = SimpleGUI()
        if gui.available:
            gui.run()
        else:
            print("[!] GUI requires tkinter. Install with: apt-get install python3-tk")
        return
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    if args.scan_type in ["syn", "null", "fin", "xmas"] and os.geteuid() != 0:
        print(f"[!] {args.scan_type.upper()} scan requires root privileges. Run with sudo.")
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
        timing=args.timing,
        os_detection=args.os_detection,
        discover_hosts=args.discover_hosts
    )
    
    try:
        results = scanner.scan()
        print_scan_results(results)
        
        if args.output:
            save_scan_results(results, args.output, args.format)
        
        if len(results.ports) == 0 and not results.discovered_hosts:
            print("\n[*] No open ports found. Try adjusting timeout or scan type.")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
