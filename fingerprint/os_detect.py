#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan OS Fingerprinting Module
Author: Meheraz HOSEN SIAM
Description: Remote operating system detection through TCP/IP stack fingerprinting
"""

import socket
import struct
import time
import random
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class OSClass(Enum):
    """Operating system classification"""
    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"
    BSD = "BSD"
    SOLARIS = "Solaris"
    CISCO = "Cisco"
    PRINTER = "Printer"
    EMBEDDED = "Embedded"
    UNKNOWN = "Unknown"


@dataclass
class OSFingerprint:
    """OS fingerprint result"""
    os_class: OSClass
    os_name: str
    os_version: Optional[str]
    accuracy: int  # 0-100
    details: Dict[str, Any]


# OS Signature Database
# Based on TCP/IP stack fingerprinting characteristics
OS_SIGNATURES = {
    # Windows signatures
    "windows": {
        "ttl": [128],
        "window_size": [8192, 65535],
        "df_bit": True,
        "tcp_options": "020405b4010303030101080a0000000000000000",
        "os_class": OSClass.WINDOWS,
        "os_names": ["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022"]
    },
    "windows_7": {
        "ttl": [128],
        "window_size": [8192],
        "df_bit": True,
        "os_class": OSClass.WINDOWS,
        "os_names": ["Windows 7", "Windows Server 2008 R2"]
    },
    "windows_xp": {
        "ttl": [128],
        "window_size": [65535],
        "df_bit": True,
        "os_class": OSClass.WINDOWS,
        "os_names": ["Windows XP", "Windows Server 2003"]
    },
    
    # Linux signatures
    "linux_modern": {
        "ttl": [64],
        "window_size": [65535, 29200],
        "df_bit": True,
        "tcp_options": "020405b40402080a0000000000000000",
        "os_class": OSClass.LINUX,
        "os_names": ["Linux 4.x/5.x", "Ubuntu 20.04+", "Debian 10+", "CentOS 8+"]
    },
    "linux_legacy": {
        "ttl": [64],
        "window_size": [5840],
        "df_bit": True,
        "os_class": OSClass.LINUX,
        "os_names": ["Linux 2.6.x", "RHEL 6", "CentOS 6"]
    },
    
    # macOS signatures
    "macos": {
        "ttl": [64],
        "window_size": [65535],
        "df_bit": True,
        "tcp_options": "020405ac010303050101080a0000000000000000",
        "os_class": OSClass.MACOS,
        "os_names": ["macOS 10.15+", "macOS 11+", "macOS 12+"]
    },
    
    # BSD signatures
    "freebsd": {
        "ttl": [64],
        "window_size": [65535],
        "df_bit": True,
        "os_class": OSClass.BSD,
        "os_names": ["FreeBSD 12+", "FreeBSD 13+"]
    },
    "openbsd": {
        "ttl": [64],
        "window_size": [16384],
        "df_bit": True,
        "os_class": OSClass.BSD,
        "os_names": ["OpenBSD 6.x", "OpenBSD 7.x"]
    },
    
    # Network devices
    "cisco_ios": {
        "ttl": [255],
        "window_size": [4128],
        "df_bit": False,
        "os_class": OSClass.CISCO,
        "os_names": ["Cisco IOS", "Cisco Catalyst"]
    },
    
    # Printers/Embedded
    "printer": {
        "ttl": [64, 128, 255],
        "window_size": [1024, 4096],
        "df_bit": False,
        "os_class": OSClass.PRINTER,
        "os_names": ["HP Printer", "Canon Printer", "Network Printer"]
    }
}


class OSFingerprinter:
    """
    Operating System Fingerprinting Engine.
    
    Uses multiple techniques:
    - TCP/IP stack fingerprinting
    - ICMP response analysis
    - Banner analysis
    - Open port pattern matching
    """
    
    # TTL to distance mapping
    TTL_DISTANCE_MAP = {
        255: 0, 128: 0, 64: 0, 32: 0,  # Common initial TTLs
        254: 1, 127: 1, 63: 1, 31: 1,
    }
    
    # Port-based OS detection patterns
    PORT_PATTERNS = {
        OSClass.WINDOWS: [135, 139, 445, 3389],
        OSClass.LINUX: [22, 111, 2049],
        OSClass.MACOS: [548, 631],
        OSClass.PRINTER: [9100, 515, 631],
        OSClass.CISCO: [22, 23, 161]
    }
    
    def __init__(self, target: str, timeout: float = 2.0, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.resolved_ip: Optional[str] = None
        self.fingerprints: List[OSFingerprint] = []
        
    def resolve_target(self) -> Optional[str]:
        """Resolve hostname to IP"""
        try:
            parts = self.target.replace('.', '').replace(':', '')
            if parts.isdigit():
                return self.target
            return socket.gethostbyname(self.target)
        except:
            return None
    
    def _get_ttl_guess(self, ttl: int) -> Tuple[OSClass, int, str]:
        """Guess OS from TTL value"""
        # Initial TTL guess
        if ttl <= 64:
            # Could be Linux/BSD/macOS or Windows with many hops
            return OSClass.LINUX, 64 - ttl + 1, "Linux/BSD/macOS"
        elif ttl <= 128:
            # Likely Windows
            return OSClass.WINDOWS, 128 - ttl + 1, "Windows"
        elif ttl <= 255:
            # Likely network device
            return OSClass.CISCO, 255 - ttl + 1, "Network Device"
        else:
            return OSClass.UNKNOWN, 0, "Unknown"
    
    def _tcp_probe(self, port: int = 80) -> Optional[Dict[str, Any]]:
        """
        Send TCP probe and capture response characteristics.
        
        Returns TCP/IP stack fingerprint data.
        """
        if not self.resolved_ip:
            return None
            
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Record start time for RTT
            start_time = time.time()
            
            # Attempt connection
            result = sock.connect_ex((self.resolved_ip, port))
            
            if result == 0:
                # Connection succeeded - get socket info
                rtt = time.time() - start_time
                
                # Get socket buffer sizes as proxy for window
                # Note: Real OS fingerprinting would capture actual SYN-ACK
                return {
                    'connected': True,
                    'rtt': rtt,
                    'port': port
                }
            
            return None
            
        except socket.error:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _icmp_probe(self) -> Optional[Dict[str, Any]]:
        """
        Send ICMP echo request and analyze response.
        
        Returns ICMP fingerprint data including TTL.
        """
        if not self.resolved_ip:
            return None
            
        try:
            # Create raw ICMP socket (requires root)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
        except (PermissionError, OSError):
            # Fall back to regular ping
            return self._udp_ping_probe()
        
        try:
            # Build ICMP echo request
            icmp_type = 8  # Echo request
            icmp_code = 0
            icmp_checksum = 0
            icmp_id = random.randint(0, 65535)
            icmp_seq = 1
            
            # Build packet
            header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
            data = b'ShadowScan-OS-Fingerprint'
            
            # Calculate checksum
            checksum = self._calculate_checksum(header + data)
            header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
            
            packet = header + data
            
            # Send and receive
            sock.sendto(packet, (self.resolved_ip, 0))
            
            start_time = time.time()
            response, addr = sock.recvfrom(1024)
            rtt = time.time() - start_time
            
            # Parse response
            if len(response) >= 28:
                # IP header is first 20 bytes
                ip_header = response[:20]
                ip_ttl = ip_header[8]
                
                # ICMP header starts at byte 20
                icmp_header = response[20:28]
                resp_type, resp_code = struct.unpack('!BB', icmp_header[:2])
                
                if resp_type == 0:  # Echo reply
                    return {
                        'ttl': ip_ttl,
                        'rtt': rtt,
                        'reachable': True
                    }
            
            return None
            
        except socket.timeout:
            return {'reachable': False}
        except Exception:
            return None
        finally:
            sock.close()
    
    def _udp_ping_probe(self) -> Optional[Dict[str, Any]]:
        """Fallback UDP-based probe for hosts that block ICMP"""
        if not self.resolved_ip:
            return None
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send to a likely closed port to trigger ICMP
            sock.sendto(b'ShadowScan', (self.resolved_ip, 33434))
            
            # Wait for any response
            start_time = time.time()
            try:
                data, addr = sock.recvfrom(1024)
                return {
                    'reachable': True,
                    'rtt': time.time() - start_time
                }
            except socket.timeout:
                # No response - host may be up but silent
                return {'reachable': 'unknown'}
                
        except Exception:
            return None
        finally:
            try:
                sock.close()
            except:
                pass
    
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        
        return ~s & 0xffff
    
    def _port_pattern_analysis(self, open_ports: List[int]) -> Optional[OSClass]:
        """Analyze open ports to guess OS"""
        if not open_ports:
            return None
            
        open_set = set(open_ports)
        
        for os_class, pattern_ports in self.PORT_PATTERNS.items():
            if any(port in open_set for port in pattern_ports):
                # Count matching ports
                matches = sum(1 for port in pattern_ports if port in open_set)
                if matches >= 2:
                    return os_class
        
        return None
    
    def fingerprint(self, open_ports: Optional[List[int]] = None) -> List[OSFingerprint]:
        """
        Perform OS fingerprinting.
        
        Args:
            open_ports: Optional list of known open ports
            
        Returns:
            List of OS fingerprints with confidence levels
        """
        self.resolved_ip = self.resolve_target()
        
        if not self.resolved_ip:
            print(f"[!] Cannot resolve {self.target}")
            return []
        
        results = []
        
        # ICMP probe for TTL
        icmp_data = self._icmp_probe()
        
        if icmp_data and 'ttl' in icmp_data:
            ttl = icmp_data['ttl']
            os_class, distance, description = self._get_ttl_guess(ttl)
            
            # Add TTL-based fingerprint
            results.append(OSFingerprint(
                os_class=os_class,
                os_name=description,
                os_version=None,
                accuracy=70,
                details={
                    'method': 'TTL analysis',
                    'ttl': ttl,
                    'estimated_distance': distance,
                    'rtt': icmp_data.get('rtt', 0)
                }
            ))
        
        # Port pattern analysis
        if open_ports:
            port_os = self._port_pattern_analysis(open_ports)
            if port_os:
                results.append(OSFingerprint(
                    os_class=port_os,
                    os_name=f"{port_os.value} (detected by port pattern)",
                    os_version=None,
                    accuracy=60,
                    details={
                        'method': 'Port pattern analysis',
                        'open_ports': open_ports
                    }
                ))
        
        # TCP probe for additional fingerprinting
        for probe_port in [80, 443, 22]:
            tcp_data = self._tcp_probe(probe_port)
            if tcp_data:
                results.append(OSFingerprint(
                    os_class=OSClass.UNKNOWN,
                    os_name="TCP Responsive Host",
                    os_version=None,
                    accuracy=50,
                    details={
                        'method': 'TCP probe',
                        'port': probe_port,
                        'rtt': tcp_data.get('rtt', 0)
                    }
                ))
                break
        
        # Sort by accuracy and store
        self.fingerprints = sorted(results, key=lambda x: x.accuracy, reverse=True)
        
        return self.fingerprints
    
    def get_best_guess(self) -> Optional[OSFingerprint]:
        """Get the most likely OS fingerprint"""
        if self.fingerprints:
            return self.fingerprints[0]
        return None
    
    def print_results(self) -> None:
        """Print fingerprinting results"""
        try:
            from colorama import Fore, Style
        except:
            Fore = type('', (), {'CYAN': '\033[96m', 'GREEN': '\033[92m', 
                                 'YELLOW': '\033[93m', 'RESET': '\033[0m'})()
            Style = type('', (), {'RESET_ALL': '\033[0m'})()
        
        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}OS FINGERPRINTING RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
        
        if not self.fingerprints:
            print(f"{Fore.YELLOW}[!] No fingerprint data collected{Style.RESET_ALL}")
            return
        
        for fp in self.fingerprints:
            accuracy_bar = '█' * (fp.accuracy // 10) + '░' * (10 - fp.accuracy // 10)
            print(f"\n{Fore.GREEN}● {fp.os_name}{Style.RESET_ALL}")
            print(f"  Class: {fp.os_class.value}")
            print(f"  Accuracy: [{accuracy_bar}] {fp.accuracy}%")
            if fp.details:
                for key, value in fp.details.items():
                    if key != 'method':
                        print(f"  {key}: {value}")
        
        best = self.get_best_guess()
        if best:
            print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Best Guess: {best.os_name} ({best.accuracy}% confidence){Style.RESET_ALL}")
