#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan Network Utilities
Author: Meheraz HOSEN SIAM
"""

import socket
import struct
import random
import time
from typing import Optional, Tuple, List


class NetworkUtils:
    """Network utility functions for scanning"""
    
    @staticmethod
    def resolve_hostname(hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            parts = hostname.replace('.', '').replace(':', '')
            if parts.isdigit():
                return hostname
            return socket.gethostbyname(hostname)
        except (socket.gaierror, socket.error):
            return None
    
    @staticmethod
    def reverse_dns(ip: str) -> Optional[str]:
        """Reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def calculate_checksum(data: bytes) -> int:
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
    
    @staticmethod
    def ip_to_bytes(ip: str) -> bytes:
        """Convert IP string to bytes"""
        return socket.inet_aton(ip)
    
    @staticmethod
    def bytes_to_ip(data: bytes) -> str:
        """Convert bytes to IP string"""
        return socket.inet_ntoa(data)
    
    @staticmethod
    def parse_port_range(port_str: str) -> List[int]:
        """
        Parse port range string.
        
        Examples:
            "22" -> [22]
            "22,80,443" -> [22, 80, 443]
            "1-1000" -> [1, 2, ..., 1000]
            "22,80,443,8000-9000" -> [22, 80, 443, 8000, ..., 9000]
        """
        ports = []
        
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number"""
        return 1 <= port <= 65535
    
    @staticmethod
    def get_random_port() -> int:
        """Get random high port number"""
        return random.randint(49152, 65535)
    
    @staticmethod
    def is_host_alive(ip: str, timeout: float = 1.0) -> bool:
        """Check if host is alive using TCP ping"""
        test_ports = [80, 443, 22, 445]
        
        for port in test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        
        return False
