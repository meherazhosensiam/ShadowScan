#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan UDP Scanner
Author: Meheraz HOSEN SIAM
Description: UDP port scanner with service detection
"""

import socket
import struct
import time
from typing import Dict, Any, Optional, List
from ..core.scanner import BaseScanner


class UDPScanner(BaseScanner):
    """
    UDP Scanner - Connectionless port scanning.
    
    UDP scanning is more challenging than TCP because:
    - No handshake, no connection state
    - Open ports often don't respond
    - Closed ports send ICMP port unreachable
    
    Techniques used:
    - Send UDP packets and analyze responses
    - Use protocol-specific payloads
    - Detect ICMP unreachable messages
    """
    
    # UDP service probes
    UDP_PROBES = {
        53: b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00',  # DNS
        67: b'\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # DHCP
        69: b'\x00\x01test\x00octet\x00',  # TFTP
        123: b'\x1b' + b'\x00' * 47,  # NTP
        137: b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01',  # NetBIOS
        161: b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa1\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
        500: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # IKE
        514: b'\x00',  # Syslog
        1812: b'\x00',  # RADIUS
    }
    
    # UDP services database
    UDP_SERVICES = {
        7: "Echo", 9: "Discard", 17: "QOTD", 19: "Chargen",
        37: "Time", 53: "DNS", 67: "DHCP", 68: "DHCP",
        69: "TFTP", 80: "HTTP-UDP", 111: "RPC", 123: "NTP",
        135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
        161: "SNMP", 162: "SNMP-Trap", 177: "XDMCP", 389: "LDAP",
        443: "HTTPS-UDP", 445: "SMB-UDP", 500: "IKE", 514: "Syslog",
        520: "RIP", 623: "IPMI", 631: "IPP", 1434: "MSSQL-Monitor",
        1645: "RADIUS", 1646: "RADIUS", 1701: "L2TP", 1812: "RADIUS",
        1813: "RADIUS", 1900: "SSDP", 4500: "IKE-NAT", 5353: "mDNS",
        5060: "SIP", 5061: "SIPS", 11211: "Memcache", 27017: "MongoDB"
    }
    
    def __init__(self, target: str, ports: Optional[List[int]] = None,
                 threads: int = 100, timeout: float = 2.0,
                 verbose: bool = False, retries: int = 2):
        super().__init__(target, ports, threads, timeout, verbose)
        self.retries = retries
        self.icmp_socket = None
        
    def get_scan_type(self) -> str:
        return "UDP Scan"
    
    def get_service_name(self, port: int) -> str:
        """Get UDP service name for port"""
        return self.UDP_SERVICES.get(port, "Unknown UDP")
    
    def _create_icmp_socket(self) -> Optional[socket.socket]:
        """Create ICMP socket for receiving unreachable messages"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            return sock
        except (PermissionError, OSError):
            return None
    
    def _send_udp_probe(self, port: int) -> Optional[bytes]:
        """Send UDP probe and return response if any"""
        if not self.resolved_ip:
            return None
            
        # Get appropriate probe
        probe = self.UDP_PROBES.get(port, b'\x00' * 8)
        
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send probe
            sock.sendto(probe, (self.resolved_ip, port))
            
            # Try to receive response
            try:
                data, addr = sock.recvfrom(1024)
                return data
            except socket.timeout:
                return None
                
        except socket.error:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    def _check_icmp_unreachable(self, port: int) -> bool:
        """Check if we received ICMP port unreachable"""
        if not self.icmp_socket:
            return False
            
        try:
            data, addr = self.icmp_socket.recvfrom(1024)
            
            # Parse ICMP header
            if len(data) < 28:
                return False
                
            # Check if it's a destination unreachable message
            icmp_type = data[20]
            icmp_code = data[21]
            
            # Type 3 = Destination Unreachable
            # Code 3 = Port Unreachable
            if icmp_type == 3 and icmp_code == 3:
                # Extract original port from embedded packet
                if len(data) >= 50:
                    original_port = struct.unpack('!H', data[50:52])[0]
                    if original_port == port:
                        return True
                        
        except socket.timeout:
            pass
        except Exception:
            pass
            
        return False
    
    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """
        Scan a single UDP port.
        
        UDP states:
        - open: Received a response
        - closed: Received ICMP port unreachable
        - open|filtered: No response
        """
        if not self.resolved_ip:
            return None
        
        # Try multiple times for reliability
        for attempt in range(self.retries + 1):
            response = self._send_udp_probe(port)
            
            if response:
                # Got a response - port is open
                service = self.get_service_name(port)
                banner = response[:100].hex() if response else None
                
                return {
                    'port': port,
                    'protocol': 'udp',
                    'state': 'open',
                    'service': service,
                    'banner': f"UDP response ({len(response)} bytes)" if response else None
                }
            
            # Check for ICMP unreachable
            if self._check_icmp_unreachable(port):
                return {
                    'port': port,
                    'protocol': 'udp',
                    'state': 'closed',
                    'service': self.get_service_name(port),
                    'banner': None
                }
            
            # Small delay between retries
            if attempt < self.retries:
                time.sleep(0.1)
        
        # No response - could be open or filtered
        return {
            'port': port,
            'protocol': 'udp',
            'state': 'open|filtered',
            'service': self.get_service_name(port),
            'banner': None
        }
    
    def pre_scan(self) -> bool:
        """Setup before UDP scan"""
        if not super().pre_scan():
            return False
        
        # Try to create ICMP socket for unreachable detection
        self.icmp_socket = self._create_icmp_socket()
        
        if not self.icmp_socket:
            print(f"{self._get_color('YELLOW')}[!] ICMP socket unavailable - limited UDP detection{self._get_color('RESET')}")
        
        return True
    
    def _get_color(self, color_name: str) -> str:
        """Get color code"""
        try:
            from colorama import Fore
            colors = {
                'RED': Fore.RED, 'GREEN': Fore.GREEN,
                'YELLOW': Fore.YELLOW, 'CYAN': Fore.CYAN,
                'MAGENTA': Fore.MAGENTA, 'RESET': '\033[0m'
            }
            return colors.get(color_name, '')
        except:
            return ''
    
    def post_scan(self) -> None:
        """Cleanup after UDP scan"""
        if self.icmp_socket:
            try:
                self.icmp_socket.close()
            except:
                pass
    
    def scan(self) -> bool:
        """Execute UDP scan"""
        # UDP scan takes longer due to retries and longer timeouts
        print(f"{self._get_color('CYAN')}[*] UDP scan may take longer due to protocol nature{self._get_color('RESET')}")
        return super().scan()
    
    def print_summary(self) -> None:
        """Print UDP scan summary with state breakdown"""
        super().print_summary()
        
        # Additional UDP-specific summary
        open_filtered = [r for r in self.results if r.get('state') == 'open|filtered']
        if open_filtered:
            print(f"\n{self._get_color('YELLOW')}[i] Open|Filtered ports ({len(open_filtered)}):{self._get_color('RESET')}")
            print(f"{self._get_color('YELLOW')}    These ports did not respond - may be open or filtered{self._get_color('RESET')}")


def quick_udp_scan(target: str, threads: int = 50) -> UDPScanner:
    """Create a quick UDP scanner for common UDP ports"""
    common_udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162,
                       500, 514, 520, 623, 1434, 1812, 1900, 5353, 5060, 11211]
    return UDPScanner(target, common_udp_ports, threads, timeout=2.0, retries=2)


def full_udp_scan(target: str, threads: int = 50) -> UDPScanner:
    """Create a full UDP scanner for all ports"""
    return UDPScanner(target, list(range(1, 65536)), threads, timeout=1.0, retries=1)
