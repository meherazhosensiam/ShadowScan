#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan - Advanced Network Port Scanner
Author: Mahara HOSEN SIAM
Description: A professional penetration testing tool for network reconnaissance
License: Shadow Public License v1.0
"""

import socket
import threading
import argparse
import sys
import time
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import platform

# Try to import colorama for cross-platform colored output
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback color codes
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
    
    class Back:
        RED = '\033[101m'
        GREEN = '\033[102m'
        YELLOW = '\033[103m'
        BLUE = '\033[104m'
        MAGENTA = '\033[105m'
        CYAN = '\033[106m'
        WHITE = '\033[107m'
        RESET = '\033[0m'
    
    class Style:
        BRIGHT = '\033[1m'
        DIM = '\033[2m'
        RESET_ALL = '\033[0m'

# Version and Tool Information
TOOL_NAME = "ShadowScan"
VERSION = "2.0.0"
AUTHOR = "Mahara HOSEN SIAM"
DESCRIPTION = "Advanced Network Port Scanner for Penetration Testing"

# Common Ports and Services Database
COMMON_PORTS = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    80: "HTTP (HyperText Transfer Protocol)",
    110: "POP3 (Post Office Protocol v3)",
    135: "RPC (Remote Procedure Call)",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (HTTP Secure)",
    445: "SMB (Server Message Block)",
    993: "IMAPS (IMAP over SSL)",
    995: "POP3S (POP3 over SSL)",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle Database",
    3306: "MySQL",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis",
    8080: "HTTP Proxy/Alternate HTTP",
    8443: "HTTPS Alternate",
    27017: "MongoDB",
}

# French Navigation Menu
FRENCH_MENU = {
    "scan": "Analyse des ports",
    "banner": "Capture de bannière",
    "full": "Analyse complète",
    "quick": "Analyse rapide",
    "export": "Exporter les résultats",
    "help": "Aide",
    "exit": "Quitter",
    "settings": "Paramètres",
    "about": "À propos"
}

# ASCII Banner
def print_banner():
    """Display the ShadowScan banner"""
    banner = f"""
{Fore.CYAN}{'═' * 70}
{Fore.MAGENTA}   ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗ ██████╗ ███████╗
{Fore.MAGENTA}   ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝ ██╔════╝
{Fore.MAGENTA}   ███████╗██║   ██║██║  ██║█████╗  ██╔██╗ ██║██║  ███╗█████╗  
{Fore.MAGENTA}   ╚════██║██║   ██║██║  ██║██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  
{Fore.MAGENTA}   ███████║╚██████╔╝██████╔╝███████╗██║ ╚████║╚██████╔╝███████╗
{Fore.MAGENTA}   ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
{Fore.CYAN}{'═' * 70}
{Fore.YELLOW}   ╔═══════════════════════════════════════════════════════════════════╗
{Fore.YELLOW}   ║  {Fore.WHITE}Advanced Network Port Scanner for Penetration Testing{Fore.YELLOW}           ║
{Fore.YELLOW}   ╠═══════════════════════════════════════════════════════════════════╣
{Fore.YELLOW}   ║  {Fore.CYAN}Version:{Fore.WHITE} {VERSION}    {Fore.CYAN}Author:{Fore.WHITE} {AUTHOR}          ║
{Fore.YELLOW}   ║  {Fore.CYAN}License:{Fore.WHITE} Shadow Public License v1.0                           ║
{Fore.YELLOW}   ╚═══════════════════════════════════════════════════════════════════╝
{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}
"""
    print(banner)

# French themed welcome message
def print_french_welcome():
    """Display French themed welcome message"""
    welcome = f"""
{Fore.BLUE}╔═══════════════════════════════════════════════════════════════════╗
{Fore.BLUE}║  {Fore.WHITE}🇫🇷 Bienvenue dans ShadowScan - Navigation France{Fore.BLUE}              ║
{Fore.BLUE}╠═══════════════════════════════════════════════════════════════════╣
{Fore.BLUE}║  {Fore.CYAN}[1]{Fore.WHITE} Analyse rapide (Quick Scan)     {Fore.CYAN}[2]{Fore.WHITE} Analyse complète      {Fore.BLUE}║
{Fore.BLUE}║  {Fore.CYAN}[3]{Fore.WHITE} Capture de bannière           {Fore.CYAN}[4]{Fore.WHITE} Ports personnalisés   {Fore.BLUE}║
{Fore.BLUE}║  {Fore.CYAN}[5]{Fore.WHITE} Détection de services         {Fore.CYAN}[6]{Fore.WHITE} Analyse UDP           {Fore.BLUE}║
{Fore.BLUE}║  {Fore.CYAN}[7]{Fore.WHITE} Exporter les résultats        {Fore.CYAN}[8]{Fore.WHITE} Paramètres            {Fore.BLUE}║
{Fore.BLUE}║  {Fore.CYAN}[9]{Fore.WHITE} À propos                     {Fore.CYAN}[0]{Fore.WHITE} Quitter               {Fore.BLUE}║
{Fore.BLUE}╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(welcome)


class ShadowScanner:
    """Main Scanner Class for ShadowScan"""
    
    def __init__(self, target, ports=None, threads=100, timeout=1, verbose=False):
        self.target = target
        self.ports = ports or list(range(1, 1025))
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.open_ports = []
        self.closed_ports = 0
        self.filtered_ports = 0
        self.scan_results = {}
        self.start_time = None
        self.end_time = None
        self.banner_grab_enabled = False
        
    def resolve_target(self):
        """Resolve hostname to IP address"""
        try:
            if self.target.replace('.', '').isdigit():
                return self.target
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            print(f"{Fore.RED}[!] Error: Unable to resolve hostname '{self.target}'{Style.RESET_ALL}")
            return None
    
    def grab_banner(self, ip, port):
        """Attempt to grab banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Try to receive banner
            try:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner[:200]  # Limit banner length
            except:
                pass
            finally:
                sock.close()
        except:
            pass
        return None
    
    def scan_port(self, port):
        """Scan a single port"""
        ip = self.resolve_target()
        if not ip:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown Service")
                banner = None
                
                if self.banner_grab_enabled:
                    banner = self.grab_banner(ip, port)
                
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
                
                sock.close()
                return port_info
            else:
                sock.close()
                return None
                
        except socket.error as e:
            return None
        except Exception as e:
            return None
    
    def scan(self):
        """Perform the port scan using multithreading"""
        ip = self.resolve_target()
        if not ip:
            return False
            
        self.start_time = datetime.now()
        
        print(f"\n{Fore.CYAN}[*] Starting ShadowScan against: {Fore.YELLOW}{self.target} ({ip}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan started at: {Fore.YELLOW}{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scanning {Fore.YELLOW}{len(self.ports)}{Fore.CYAN} ports with {Fore.YELLOW}{self.threads}{Fore.CYAN} threads{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)
                    self.print_port_result(result)
        
        self.end_time = datetime.now()
        self.open_ports.sort(key=lambda x: x['port'])
        return True
    
    def print_port_result(self, result):
        """Print individual port result"""
        port = result['port']
        service = result['service']
        banner = result.get('banner', '')
        
        # Color code by port type
        if port in [22, 443, 993, 995]:
            color = Fore.GREEN  # Secure ports
        elif port in [21, 23, 80, 8080]:
            color = Fore.YELLOW  # Common ports
        elif port in [135, 139, 445, 3389]:
            color = Fore.RED  # Potentially vulnerable ports
        else:
            color = Fore.CYAN
        
        print(f"{color}[+] Port {port:5d}/tcp  {Fore.WHITE}OPEN    {Fore.MAGENTA}{service[:40]}{Style.RESET_ALL}")
        
        if banner and self.verbose:
            print(f"    {Fore.DIM}└── Banner: {banner[:100]}...{Style.RESET_ALL}")
    
    def print_summary(self):
        """Print scan summary"""
        if not self.end_time:
            return
            
        duration = (self.end_time - self.start_time).total_seconds()
        
        print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Scan Complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: {Fore.YELLOW}{self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Open Ports: {Fore.GREEN}{len(self.open_ports)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Scan Duration: {Fore.YELLOW}{duration:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Finished: {Fore.YELLOW}{self.end_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        
        if self.open_ports:
            print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}OPEN PORTS SUMMARY:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
            
            for result in self.open_ports:
                port = result['port']
                service = result['service']
                print(f"  {Fore.GREEN}●{Fore.WHITE} {port:5d}/tcp  →  {Fore.CYAN}{service}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
    
    def export_results(self, filename, format_type='json'):
        """Export scan results to file"""
        export_data = {
            'tool': TOOL_NAME,
            'version': VERSION,
            'author': AUTHOR,
            'target': self.target,
            'scan_date': str(self.start_time) if self.start_time else None,
            'duration': str(self.end_time - self.start_time) if self.end_time else None,
            'total_open_ports': len(self.open_ports),
            'open_ports': self.open_ports
        }
        
        try:
            if format_type.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=4)
            elif format_type.lower() == 'txt':
                with open(filename, 'w') as f:
                    f.write(f"ShadowScan Results\n")
                    f.write(f"{'=' * 50}\n")
                    f.write(f"Target: {self.target}\n")
                    f.write(f"Scan Date: {self.start_time}\n")
                    f.write(f"Open Ports: {len(self.open_ports)}\n")
                    f.write(f"{'=' * 50}\n\n")
                    for port_info in self.open_ports:
                        f.write(f"Port {port_info['port']}/tcp - {port_info['service']}\n")
                        if port_info.get('banner'):
                            f.write(f"  Banner: {port_info['banner']}\n")
            
            print(f"{Fore.GREEN}[✓] Results exported to: {filename}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error exporting results: {e}{Style.RESET_ALL}")
            return False


def quick_scan(target, threads=100):
    """Perform a quick scan on common ports"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 
                   1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    
    print(f"{Fore.CYAN}[*] Running Quick Scan on {len(common_ports)} common ports...{Style.RESET_ALL}")
    scanner = ShadowScanner(target, common_ports, threads, banner_grab_enabled=True)
    return scanner


def full_scan(target, threads=100):
    """Perform a full scan on all ports (1-65535)"""
    print(f"{Fore.CYAN}[*] Running Full Scan on all 65535 ports...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] This may take a while...{Style.RESET_ALL}")
    scanner = ShadowScanner(target, list(range(1, 65536)), threads, timeout=0.5)
    return scanner


def custom_scan(target, port_range, threads=100):
    """Perform a scan on custom port range"""
    if '-' in port_range:
        start, end = map(int, port_range.split('-'))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p.strip()) for p in port_range.split(',')]
    
    print(f"{Fore.CYAN}[*] Running Custom Scan on {len(ports)} ports...{Style.RESET_ALL}")
    scanner = ShadowScanner(target, ports, threads)
    return scanner


def service_detection(target, ports):
    """Detect services running on specified ports"""
    print(f"{Fore.CYAN}[*] Running Service Detection...{Style.RESET_ALL}")
    scanner = ShadowScanner(target, ports, banner_grab_enabled=True, verbose=True)
    return scanner


def interactive_mode():
    """Run ShadowScan in interactive mode with French navigation"""
    print_banner()
    print_french_welcome()
    
    while True:
        try:
            choice = input(f"\n{Fore.GREEN}ShadowScan>{Fore.WHITE} ").strip()
            
            if choice == '0' or choice.lower() == 'exit':
                print(f"\n{Fore.CYAN}[*] Merci d'utiliser ShadowScan! (Thank you for using ShadowScan!){Style.RESET_ALL}")
                print(f"{Fore.CYAN}[*] Au revoir! (Goodbye!){Style.RESET_ALL}\n")
                break
            
            elif choice == '1':
                target = input(f"{Fore.CYAN}[*] Enter target IP/hostname: {Fore.WHITE}")
                scanner = quick_scan(target)
                scanner.scan()
                scanner.print_summary()
                
                save = input(f"\n{Fore.CYAN}[*] Save results? (y/n): {Fore.WHITE}").lower()
                if save == 'y':
                    filename = input(f"{Fore.CYAN}[*] Enter filename: {Fore.WHITE}")
                    scanner.export_results(filename, 'json')
            
            elif choice == '2':
                target = input(f"{Fore.CYAN}[*] Enter target IP/hostname: {Fore.WHITE}")
                scanner = full_scan(target)
                scanner.scan()
                scanner.print_summary()
            
            elif choice == '3':
                target = input(f"{Fore.CYAN}[*] Enter target IP/hostname: {Fore.WHITE}")
                port = int(input(f"{Fore.CYAN}[*] Enter port: {Fore.WHITE}"))
                scanner = ShadowScanner(target, [port])
                scanner.banner_grab_enabled = True
                scanner.scan()
                scanner.print_summary()
            
            elif choice == '4':
                target = input(f"{Fore.CYAN}[*] Enter target IP/hostname: {Fore.WHITE}")
                port_range = input(f"{Fore.CYAN}[*] Enter port range (e.g., 1-1000 or 22,80,443): {Fore.WHITE}")
                scanner = custom_scan(target, port_range)
                scanner.scan()
                scanner.print_summary()
            
            elif choice == '5':
                target = input(f"{Fore.CYAN}[*] Enter target IP/hostname: {Fore.WHITE}")
                ports = input(f"{Fore.CYAN}[*] Enter ports (comma-separated): {Fore.WHITE}")
                port_list = [int(p.strip()) for p in ports.split(',')]
                scanner = service_detection(target, port_list)
                scanner.scan()
                scanner.print_summary()
            
            elif choice == '7':
                filename = input(f"{Fore.CYAN}[*] Enter filename for export: {Fore.WHITE}")
                format_type = input(f"{Fore.CYAN}[*] Format (json/txt): {Fore.WHITE}")
                print(f"{Fore.YELLOW}[!] Note: Export is available after a scan{Style.RESET_ALL}")
            
            elif choice == '9':
                print_banner()
                print(f"""
{Fore.CYAN}{'═' * 60}
{Fore.MAGENTA}  ABOUT SHADOWSCAN
{Fore.CYAN}{'═' * 60}
{Fore.WHITE}
  ShadowScan is an advanced network port scanner designed
  for penetration testers and cybersecurity professionals.
  
  Features:
  {Fore.GREEN}●{Fore.WHITE} Multi-threaded scanning for speed
  {Fore.GREEN}●{Fore.WHITE} Service detection and banner grabbing
  {Fore.GREEN}●{Fore.WHITE} Custom port range scanning
  {Fore.GREEN}●{Fore.WHITE} Export results to JSON/TXT
  {Fore.GREEN}●{Fore.WHITE} French navigation interface
  {Fore.GREEN}●{Fore.WHITE} Color-coded output
  
{Fore.CYAN}  Author: {Fore.YELLOW}Mahara HOSEN SIAM
{Fore.CYAN}  Role: {Fore.YELLOW}Cybersecurity Learner & Future Penetration Tester
{Fore.CYAN}  Version: {Fore.YELLOW}{VERSION}
{Fore.CYAN}  License: {Fore.YELLOW}Shadow Public License v1.0
{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}
""")
            
            else:
                print(f"{Fore.RED}[!] Invalid option. Please try again.{Style.RESET_ALL}")
                print_french_welcome()
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Interrupted. Type '0' or 'exit' to quit.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")


def main():
    """Main entry point for ShadowScan"""
    parser = argparse.ArgumentParser(
        description=f'{TOOL_NAME} v{VERSION} - Advanced Network Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s -t 192.168.1.1                    # Quick scan common ports
  %(prog)s -t example.com --full             # Full port scan
  %(prog)s -t 10.0.0.1 -p 22,80,443         # Scan specific ports
  %(prog)s -t 192.168.1.1 -p 1-1000         # Scan port range
  %(prog)s -i                               # Interactive mode
  
Author: {AUTHOR}
License: Shadow Public License v1.0
        """
    )
    
    parser.add_argument('-t', '--target', type=str, help='Target IP or hostname')
    parser.add_argument('-p', '--ports', type=str, help='Port range (e.g., 1-1000) or comma-separated (e.g., 22,80,443)')
    parser.add_argument('--full', action='store_true', help='Full port scan (1-65535)')
    parser.add_argument('--quick', action='store_true', help='Quick scan on common ports')
    parser.add_argument('-b', '--banner', action='store_true', help='Enable banner grabbing')
    parser.add_argument('-th', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('-to', '--timeout', type=float, default=1.0, help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-e', '--export', type=str, help='Export results to file (JSON or TXT)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--version', action='version', version=f'{TOOL_NAME} v{VERSION}')
    
    args = parser.parse_args()
    
    # Interactive mode
    if args.interactive or len(sys.argv) == 1:
        interactive_mode()
        return
    
    # Validate target
    if not args.target:
        parser.print_help()
        print(f"\n{Fore.RED}[!] Error: Target is required. Use -t or --target{Style.RESET_ALL}")
        sys.exit(1)
    
    print_banner()
    
    # Determine scan type
    if args.full:
        scanner = full_scan(args.target, args.threads)
    elif args.quick:
        scanner = quick_scan(args.target, args.threads)
    elif args.ports:
        scanner = custom_scan(args.target, args.ports, args.threads)
    else:
        # Default to quick scan
        scanner = quick_scan(args.target, args.threads)
    
    # Configure scanner
    scanner.banner_grab_enabled = args.banner
    scanner.verbose = args.verbose
    scanner.timeout = args.timeout
    
    # Run scan
    success = scanner.scan()
    
    if success:
        scanner.print_summary()
        
        # Export if requested
        if args.export:
            format_type = 'json' if args.export.endswith('.json') else 'txt'
            scanner.export_results(args.export, format_type)


if __name__ == "__main__":
    main()
