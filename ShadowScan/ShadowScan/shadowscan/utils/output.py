#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan Output Formatter
Author: Meheraz HOSEN SIAM
"""

import json
from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS = True
except:
    COLORS = False
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


class OutputFormatter:
    """Output formatting utilities"""
    
    @staticmethod
    def print_banner() -> None:
        """Print ShadowScan banner"""
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
{Fore.YELLOW}   ║  {Fore.CYAN}Version:{Fore.WHITE} 2.0.0    {Fore.CYAN}Author:{Fore.WHITE} Meheraz HOSEN SIAM          ║
{Fore.YELLOW}   ║  {Fore.CYAN}License:{Fore.WHITE} Shadow Public License v1.0                           ║
{Fore.YELLOW}   ╚═══════════════════════════════════════════════════════════════════╝
{Fore.CYAN}{'═' * 70}{Style.RESET_ALL}
"""
        print(banner)
    
    @staticmethod
    def print_menu() -> None:
        """Print main menu"""
        menu = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║  {Fore.WHITE}🇫🇷 Bienvenue dans ShadowScan - Navigation France{Fore.CYAN}              ║
{Fore.CYAN}╠═══════════════════════════════════════════════════════════════════╣
{Fore.CYAN}║  {Fore.WHITE}[1] TCP Quick Scan    {Fore.CYAN}[2] TCP Full Scan    {Fore.WHITE}[3] SYN Scan     {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}[4] UDP Scan          {Fore.CYAN}[5] Custom Ports     {Fore.WHITE}[6] Banner Grab  {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}[7] OS Fingerprint    {Fore.CYAN}[8] Export Results   {Fore.WHITE}[9] About        {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}[0] Exit                                                                    {Fore.CYAN}║
{Fore.CYAN}╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(menu)
    
    @staticmethod
    def print_error(message: str) -> None:
        """Print error message"""
        print(f"{Fore.RED}[!] Error: {message}{Style.RESET_ALL}")
    
    @staticmethod
    def print_success(message: str) -> None:
        """Print success message"""
        print(f"{Fore.GREEN}[✓] {message}{Style.RESET_ALL}")
    
    @staticmethod
    def print_info(message: str) -> None:
        """Print info message"""
        print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")
    
    @staticmethod
    def print_warning(message: str) -> None:
        """Print warning message"""
        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
    
    @staticmethod
    def print_port_result(port: int, protocol: str, state: str, service: str,
                          banner: Optional[str] = None) -> None:
        """Print port scan result"""
        # Color by port type
        if state == 'open':
            if port in [22, 443, 993, 995, 636, 465]:
                color = Fore.GREEN
            elif port in [21, 23, 80, 8080]:
                color = Fore.YELLOW
            elif port in [135, 139, 445, 3389]:
                color = Fore.RED
            else:
                color = Fore.CYAN
        else:
            color = Fore.MAGENTA
        
        print(f"{color}[+] Port {port:5d}/{protocol:3s}  {state.upper():12s}  {service}{Style.RESET_ALL}")
        
        if banner:
            print(f"    {Fore.WHITE}└── {banner[:80]}{Style.RESET_ALL}")
    
    @staticmethod
    def format_json(data: Dict, indent: int = 4) -> str:
        """Format data as JSON string"""
        return json.dumps(data, indent=indent, default=str)
    
    @staticmethod
    def format_table(headers: List[str], rows: List[List[Any]]) -> str:
        """Format data as ASCII table"""
        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        
        # Build table
        separator = '+' + '+'.join('-' * (w + 2) for w in widths) + '+'
        
        lines = [separator]
        lines.append('| ' + ' | '.join(h.ljust(w) for h, w in zip(headers, widths)) + ' |')
        lines.append(separator)
        
        for row in rows:
            lines.append('| ' + ' | '.join(str(c).ljust(w) for c, w in zip(row, widths)) + ' |')
        lines.append(separator)
        
        return '\n'.join(lines)
    
    @staticmethod
    def progress_bar(current: int, total: int, length: int = 50) -> str:
        """Generate progress bar string"""
        percent = (current / total) * 100
        filled = int((current / total) * length)
        bar = '█' * filled + '░' * (length - filled)
        return f"[{bar}] {percent:.1f}% ({current}/{total})"
