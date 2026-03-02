#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan TCP Connect Scanner
Author: Meheraz HOSEN SIAM
Description: Standard TCP connect scan with banner grabbing
"""

import socket
from typing import Dict, Any, Optional, List
from ..core.scanner import BaseScanner


class TCPScanner(BaseScanner):
    """
    TCP Connect Scanner - Standard full TCP handshake scan.
    
    This scanner completes the full TCP three-way handshake:
    1. Send SYN
    2. Receive SYN-ACK  
    3. Send ACK
    
    This is the most reliable scan type but is easily detected.
    """
    
    def __init__(self, target: str, ports: Optional[List[int]] = None,
                 threads: int = 100, timeout: float = 1.0, 
                 verbose: bool = False, banner_grab: bool = False):
        super().__init__(target, ports, threads, timeout, verbose)
        self.banner_grab = banner_grab
        
    def get_scan_type(self) -> str:
        return "TCP Connect Scan"
    
    def grab_banner(self, port: int) -> Optional[str]:
        """
        Attempt to grab banner from an open port.
        
        Uses various probing techniques:
        - HTTP request for web ports
        - Null probe for service response
        - Protocol-specific probes
        """
        if not self.resolved_ip:
            return None
            
        probes = self._get_probes(port)
        
        for probe in probes:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.resolved_ip, port))
                
                # Send probe
                if probe:
                    sock.send(probe)
                
                # Receive response
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                if banner:
                    return banner[:200]  # Limit length
                    
            except (socket.timeout, socket.error, ConnectionResetError):
                continue
            except Exception:
                continue
                
        return None
    
    def _get_probes(self, port: int) -> List[bytes]:
        """Get appropriate probes for a port"""
        probes = [b'']  # Start with null probe
        
        # HTTP probe for web ports
        if port in [80, 8080, 8000, 8888, 3000]:
            probes.append(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
            probes.append(b'HEAD / HTTP/1.0\r\n\r\n')
        
        # HTTPS probe
        elif port in [443, 8443]:
            probes.append(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n')
        
        # SSH probe
        elif port == 22:
            probes.append(b'SSH-2.0-ShadowScan\r\n')
        
        # FTP probe
        elif port == 21:
            probes.append(b'USER anonymous\r\n')
        
        # SMTP probe
        elif port in [25, 587, 465]:
            probes.append(b'EHLO localhost\r\n')
        
        # POP3 probe
        elif port in [110, 995]:
            probes.append(b'CAPA\r\n')
        
        # IMAP probe
        elif port in [143, 993]:
            probes.append(b'a001 CAPABILITY\r\n')
        
        # MySQL probe
        elif port == 3306:
            probes.append(b'\x00\x00\x00\x00\x00')
        
        return probes
    
    def scan_port(self, port: int) -> Optional[Dict[str, Any]]:
        """
        Scan a single TCP port using full connect.
        
        Returns port info dict if open, None otherwise.
        """
        if not self.resolved_ip:
            return None
            
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((self.resolved_ip, port))
            
            if result == 0:
                # Port is open
                service = self.get_service_name(port)
                banner = None
                
                if self.banner_grab:
                    banner = self.grab_banner(port)
                
                return {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
            
            return None
            
        except socket.error:
            return None
        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass


def quick_tcp_scan(target: str, threads: int = 100) -> TCPScanner:
    """Create a quick TCP scanner for common ports"""
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
        8080, 8443, 9200, 27017
    ]
    return TCPScanner(target, common_ports, threads, banner_grab=True)


def full_tcp_scan(target: str, threads: int = 100) -> TCPScanner:
    """Create a full TCP scanner for all ports"""
    return TCPScanner(target, list(range(1, 65536)), threads, timeout=0.5)
