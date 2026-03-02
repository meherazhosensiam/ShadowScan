#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan Base Scanner Module
Author: Meheraz HOSEN SIAM
"""

import socket
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from colorama import Fore, Style
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        MAGENTA = '\033[95m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
    class Style:
        RESET_ALL = '\033[0m'


class BaseScanner(ABC):
    """Abstract base class for all scanner types"""
    
    # Common service ports database
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
        80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
        135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
        143: "IMAP", 161: "SNMP", 162: "SNMP", 389: "LDAP",
        443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
        515: "LPR", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
        995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
        1723: "PPTP", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 5901: "VNC", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "PHP-FPM",
        9200: "Elasticsearch", 27017: "MongoDB", 28017: "MongoDB-Web"
    }
    
    def __init__(self, target: str, ports: Optional[List[int]] = None,
                 threads: int = 100, timeout: float = 1.0, verbose: bool = False):
        self.target = target
        self.ports = ports or list(range(1, 1025))
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.resolved_ip: Optional[str] = None
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.results: List[Dict[str, Any]] = []
        self.scan_errors: int = 0
        
    def resolve_target(self) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            # Check if already an IP
            parts = self.target.replace('.', '').replace(':', '')
            if parts.isdigit():
                return self.target
            return socket.gethostbyname(self.target)
        except (socket.gaierror, socket.error):
            return None
    
    def get_service_name(self, port: int) -> str:
        """Get service name for port"""
        return self.COMMON_PORTS.get(port, "Unknown")
    
    @abstractmethod
    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single port - must be implemented by subclasses"""
        pass
    
    @abstractmethod
    def get_scan_type(self) -> str:
        """Return scan type name"""
        pass
    
    def pre_scan(self) -> bool:
        """Called before scan starts - override for setup"""
        self.resolved_ip = self.resolve_target()
        if not self.resolved_ip:
            print(f"{Fore.RED}[!] Error: Unable to resolve hostname '{self.target}'{Style.RESET_ALL}")
            return False
        return True
    
    def post_scan(self) -> None:
        """Called after scan completes - override for cleanup"""
        pass
    
    def scan(self) -> bool:
        """Execute the scan with thread pool"""
        if not self.pre_scan():
            return False
        
        self.start_time = datetime.now()
        self.results = []
        
        print(f"\n{Fore.CYAN}[*] Starting {self.get_scan_type()} against: {Fore.YELLOW}{self.target} ({self.resolved_ip}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan started at: {Fore.YELLOW}{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scanning {Fore.YELLOW}{len(self.ports)}{Fore.CYAN} ports with {Fore.YELLOW}{self.threads}{Fore.CYAN} threads{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Press {Fore.YELLOW}Ctrl+C{Fore.CYAN} to stop{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")
        
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.scan_port, port): port for port in self.ports}
                
                try:
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            if result:
                                self.results.append(result)
                                self.print_result(result)
                        except Exception as e:
                            self.scan_errors += 1
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}[!] Scan interrupted{Style.RESET_ALL}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan cancelled{Style.RESET_ALL}")
        
        self.end_time = datetime.now()
        self.post_scan()
        return True
    
    def print_result(self, result: Dict[str, Any]) -> None:
        """Print scan result"""
        port = result.get('port', 0)
        state = result.get('state', 'unknown')
        service = result.get('service', 'Unknown')
        
        # Color by state and port
        if state == 'open':
            if port in [22, 443, 993, 995, 636, 465]:
                color = Fore.GREEN  # Secure
            elif port in [21, 23, 80, 8080]:
                color = Fore.YELLOW  # Common
            elif port in [135, 139, 445, 3389]:
                color = Fore.RED  # Potentially risky
            else:
                color = Fore.CYAN
        else:
            color = Fore.MAGENTA
        
        extra = ""
        if 'banner' in result and result['banner'] and self.verbose:
            extra = f"\n    {Fore.WHITE}└── Banner: {result['banner'][:80]}{Style.RESET_ALL}"
        
        print(f"{color}[+] Port {port:5d}/{result.get('protocol', 'tcp'):3s}  {state.upper():8s}  {service}{Style.RESET_ALL}{extra}")
    
    def print_summary(self) -> None:
        """Print scan summary"""
        if not self.end_time:
            return
            
        duration = (self.end_time - self.start_time).total_seconds()
        open_ports = [r for r in self.results if r.get('state') == 'open']
        
        print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Scan Complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: {Fore.YELLOW}{self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan Type: {Fore.YELLOW}{self.get_scan_type()}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Open Ports: {Fore.GREEN}{len(open_ports)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Duration: {Fore.YELLOW}{duration:.2f} seconds{Style.RESET_ALL}")
        
        if open_ports:
            print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}OPEN PORTS:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
            for r in sorted(open_ports, key=lambda x: x['port']):
                print(f"  {Fore.GREEN}●{Style.RESET_ALL} {r['port']:5d}/{r.get('protocol', 'tcp')}  →  {r['service']}")
        
        print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
    
    def export_results(self, filename: str, format_type: str = 'json') -> bool:
        """Export results to file"""
        import json
        
        data = {
            'tool': 'ShadowScan',
            'version': '2.0.0',
            'author': 'Meheraz HOSEN SIAM',
            'scan_type': self.get_scan_type(),
            'target': self.target,
            'resolved_ip': self.resolved_ip,
            'start_time': str(self.start_time) if self.start_time else None,
            'end_time': str(self.end_time) if self.end_time else None,
            'results': self.results
        }
        
        try:
            if format_type == 'json':
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=4)
            else:
                with open(filename, 'w') as f:
                    f.write(f"ShadowScan Results - {self.get_scan_type()}\n")
                    f.write(f"{'=' * 50}\n")
                    f.write(f"Target: {self.target} ({self.resolved_ip})\n\n")
                    for r in self.results:
                        if r.get('state') == 'open':
                            f.write(f"Port {r['port']}: {r['service']}\n")
            print(f"{Fore.GREEN}[✓] Results exported to: {filename}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Export failed: {e}{Style.RESET_ALL}")
            return False
