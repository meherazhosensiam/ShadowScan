#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan SYN Scanner (Stealth Scan)
Author: Meheraz HOSEN SIAM
Description: TCP SYN scan for stealthy port detection
"""

import socket
import struct
import random
import time
import threading
from typing import Dict, Any, Optional, List
from ..core.scanner import BaseScanner

# Check for raw socket capability
try:
    import socket
    RAW_SOCKETS_AVAILABLE = hasattr(socket, 'AF_PACKET') or hasattr(socket, 'AF_INET')
except:
    RAW_SOCKETS_AVAILABLE = False


class SYNScanner(BaseScanner):
    """
    SYN Scanner (Stealth Scan) - Half-open TCP scan.
    
    This scanner only sends SYN packets and analyzes responses:
    1. Send SYN packet
    2. Receive SYN-ACK (port open) or RST (port closed)
    3. No ACK sent (half-open connection)
    
    Advantages:
    - Faster than full connect
    - Less likely to be logged
    - Can detect filtered ports
    
    Requires: Raw socket capability (root/admin privileges)
    """
    
    def __init__(self, target: str, ports: Optional[List[int]] = None,
                 threads: int = 100, timeout: float = 1.0,
                 verbose: bool = False, interface: str = None):
        super().__init__(target, ports, threads, timeout, verbose)
        self.interface = interface
        self.source_port = random.randint(1024, 65535)
        self._results_lock = threading.Lock()
        self._raw_socket = None
        self._sniffer_thread = None
        self._running = False
        
        # Check for raw socket availability
        if not RAW_SOCKETS_AVAILABLE:
            self._raw_socket_supported = False
        else:
            self._raw_socket_supported = self._check_raw_socket_support()
    
    def _check_raw_socket_support(self) -> bool:
        """Check if we can create raw sockets (requires root)"""
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            test_sock.close()
            return True
        except (PermissionError, OSError):
            return False
    
    def get_scan_type(self) -> str:
        return "SYN Scan (Stealth)"
    
    def pre_scan(self) -> bool:
        """Initialize raw socket for SYN scan"""
        if not super().pre_scan():
            return False
            
        if not self._raw_socket_supported:
            print(f"{self._get_color('YELLOW')}[!] Raw sockets not available - falling back to TCP connect scan{self._get_color('RESET')}")
            print(f"{self._get_color('YELLOW')}[!] SYN scan requires root/admin privileges{self._get_color('RESET')}")
            return False
            
        try:
            # Create raw socket for sending SYN packets
            self._raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self._raw_socket.settimeout(self.timeout)
            
            # Start sniffer thread
            self._running = True
            self._sniffer_thread = threading.Thread(target=self._sniffer, daemon=True)
            self._sniffer_thread.start()
            
            return True
            
        except (PermissionError, OSError) as e:
            print(f"{self._get_color('RED')}[!] Permission denied: SYN scan requires root privileges{self._get_color('RESET')}")
            return False
    
    def _get_color(self, color_name: str) -> str:
        """Get color code"""
        try:
            from colorama import Fore
            colors = {
                'RED': Fore.RED, 'GREEN': Fore.GREEN,
                'YELLOW': Fore.YELLOW, 'CYAN': Fore.CYAN,
                'RESET': '\033[0m'
            }
            return colors.get(color_name, '')
        except:
            return ''
    
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate IP checksum"""
        if len(data) % 2 != 0:
            data += b'\x00'
        
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        
        return ~s & 0xffff
    
    def _create_syn_packet(self, dest_port: int) -> bytes:
        """Create a TCP SYN packet"""
        if not self.resolved_ip:
            return b''
            
        # Get local IP
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except:
            local_ip = '127.0.0.1'
        
        # Convert IPs to bytes
        src_addr = socket.inet_aton(local_ip)
        dst_addr = socket.inet_aton(self.resolved_ip)
        
        # TCP header fields
        src_port = self.source_port
        dst_port = dest_port
        seq_num = random.randint(0, 0xffffffff)
        ack_num = 0
        data_offset = (5 << 4)  # 5 * 4 = 20 bytes header
        flags = 0x02  # SYN flag
        window = 65535
        checksum = 0
        urgent_ptr = 0
        
        # Build TCP header
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port,
            seq_num, ack_num,
            data_offset, flags,
            window, checksum, urgent_ptr
        )
        
        # Pseudo header for checksum
        pseudo_header = struct.pack('!4s4sBBH',
            src_addr, dst_addr,
            0, socket.IPPROTO_TCP, len(tcp_header)
        )
        
        # Calculate checksum
        checksum = self._calculate_checksum(pseudo_header + tcp_header)
        
        # Rebuild with checksum
        tcp_header = struct.pack('!HHIIBBHHH',
            src_port, dst_port,
            seq_num, ack_num,
            data_offset, flags,
            window, checksum, urgent_ptr
        )
        
        return tcp_header
    
    def _sniffer(self) -> None:
        """Background thread to sniff for responses"""
        while self._running:
            try:
                response = self._raw_socket.recv(65535)
                self._parse_response(response)
            except socket.timeout:
                continue
            except Exception:
                continue
    
    def _parse_response(self, packet: bytes) -> None:
        """Parse incoming packet for SYN-ACK or RST"""
        try:
            # IP header is 20 bytes, TCP header starts after
            if len(packet) < 40:
                return
                
            # Extract TCP header
            tcp_header = packet[20:40]
            tcp_fields = struct.unpack('!HHIIBBHHH', tcp_header)
            
            src_port = tcp_fields[0]
            flags = tcp_fields[5]
            
            # Check if this is a response to our scan
            if src_port in self.ports:
                with self._results_lock:
                    if flags & 0x12:  # SYN-ACK
                        state = 'open'
                    elif flags & 0x04:  # RST
                        state = 'closed'
                    else:
                        return
                    
                    self.results.append({
                        'port': src_port,
                        'protocol': 'tcp',
                        'state': state,
                        'service': self.get_service_name(src_port),
                        'banner': None
                    })
                    
        except Exception:
            pass
    
    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Send SYN packet to port"""
        if not self._raw_socket or not self.resolved_ip:
            return None
            
        try:
            # Create and send SYN packet
            syn_packet = self._create_syn_packet(port)
            if syn_packet:
                self._raw_socket.sendto(syn_packet, (self.resolved_ip, port))
            
            # Response is handled by sniffer thread
            return None  # Results collected by sniffer
            
        except Exception:
            return None
    
    def post_scan(self) -> None:
        """Cleanup after scan"""
        self._running = False
        
        if self._raw_socket:
            try:
                self._raw_socket.close()
            except:
                pass
        
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=1.0)
    
    def scan(self) -> bool:
        """
        Execute SYN scan.
        
        Note: This overrides base scan() because SYN scan works differently.
        We send all SYN packets first, then wait for responses.
        """
        if not self.pre_scan():
            return False
        
        self.start_time = time.time()
        
        print(f"\n{self._get_color('CYAN')}[*] Starting SYN Scan against: {self._get_color('YELLOW')}{self.target} ({self.resolved_ip}){self._get_color('RESET')}")
        print(f"{self._get_color('CYAN')}[*] Scanning {self._get_color('YELLOW')}{len(self.ports)}{self._get_color('CYAN')} ports{self._get_color('RESET')}")
        print(f"{self._get_color('CYAN')}[*] Press {self._get_color('YELLOW')}Ctrl+C{self._get_color('CYAN')} to stop{self._get_color('RESET')}")
        print(f"{self._get_color('CYAN')}{'─' * 60}{self._get_color('RESET')}\n")
        
        try:
            # Send SYN packets
            for port in self.ports:
                if not self._running:
                    break
                self.scan_port(port)
            
            # Wait for responses
            time.sleep(self.timeout * 2)
            
        except KeyboardInterrupt:
            print(f"\n{self._get_color('YELLOW')}[!] Scan interrupted{self._get_color('RESET')}")
        
        self.post_scan()
        
        # Print results
        open_ports = [r for r in self.results if r.get('state') == 'open']
        for result in sorted(open_ports, key=lambda x: x['port']):
            self.print_result(result)
        
        return True


def quick_syn_scan(target: str, threads: int = 100) -> SYNScanner:
    """Create a quick SYN scanner for common ports"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
    return SYNScanner(target, common_ports, threads)
