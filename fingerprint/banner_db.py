#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan Banner Fingerprint Database
Author: Meheraz HOSEN SIAM
Description: Comprehensive banner analysis and service fingerprinting
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class ServiceCategory(Enum):
    """Service category classification"""
    WEB_SERVER = "Web Server"
    MAIL_SERVER = "Mail Server"
    DATABASE = "Database"
    FILE_SERVER = "File Server"
    REMOTE_ACCESS = "Remote Access"
    DNS = "DNS"
    PROXY = "Proxy"
    VPN = "VPN"
    APPLICATION = "Application"
    UNKNOWN = "Unknown"


@dataclass
class ServiceFingerprint:
    """Service fingerprint from banner"""
    service_name: str
    version: Optional[str]
    category: ServiceCategory
    vendor: Optional[str]
    cpe: Optional[str]  # Common Platform Enumeration
    confidence: int
    vulnerabilities: List[str]  # Known CVE patterns
    additional_info: Dict[str, Any]


# Comprehensive Banner Database
BANNER_SIGNATURES = {
    # SSH Signatures
    r'^SSH-([\d.]+)-([^\r\n]+)': {
        'service': 'SSH',
        'category': ServiceCategory.REMOTE_ACCESS,
        'version_group': 2,
        'vendor_extract': r'SSH-[\d.]+-(OpenSSH|Dropbear|libssh|Cisco)',
        'cpe_template': 'a:ssh:{vendor}:{version}',
    },
    
    # HTTP Server Signatures
    r'^HTTP/[\d.]+\s+\d+': {
        'service': 'HTTP Response',
        'category': ServiceCategory.WEB_SERVER,
    },
    r'^Server:\s*([^\r\n]+)': {
        'service': 'HTTP Server',
        'category': ServiceCategory.WEB_SERVER,
        'version_group': 1,
    },
    
    # Apache
    r'Apache[/\s]?([\d.]+)?': {
        'service': 'Apache HTTPD',
        'category': ServiceCategory.WEB_SERVER,
        'version_group': 1,
        'vendor': 'Apache',
        'cpe_template': 'a:apache:httpd:{version}',
    },
    
    # Nginx
    r'nginx[/\s]?([\d.]+)?': {
        'service': 'Nginx',
        'category': ServiceCategory.WEB_SERVER,
        'version_group': 1,
        'vendor': 'Nginx',
        'cpe_template': 'a:nginx:nginx:{version}',
    },
    
    # Microsoft IIS
    r'Microsoft-IIS[/\s]?([\d.]+)?': {
        'service': 'Microsoft IIS',
        'category': ServiceCategory.WEB_SERVER,
        'version_group': 1,
        'vendor': 'Microsoft',
        'cpe_template': 'a:microsoft:iis:{version}',
    },
    
    # FTP Signatures
    r'^(\d{3})\s+([^\r\n]+)': {
        'service': 'FTP',
        'category': ServiceCategory.FILE_SERVER,
    },
    r'(ProFTPD)[\s/]?([\d.]+)?': {
        'service': 'ProFTPD',
        'category': ServiceCategory.FILE_SERVER,
        'version_group': 2,
        'vendor': 'ProFTPD',
    },
    r'(vsftpd)[\s/]?([\d.]+)?': {
        'service': 'vsftpd',
        'category': ServiceCategory.FILE_SERVER,
        'version_group': 2,
        'vendor': 'vsftpd',
    },
    r'(FileZilla)[\s/]?([\d.]+)?': {
        'service': 'FileZilla FTP',
        'category': ServiceCategory.FILE_SERVER,
        'version_group': 2,
        'vendor': 'FileZilla',
    },
    r'(Pure-FTPd)': {
        'service': 'Pure-FTPd',
        'category': ServiceCategory.FILE_SERVER,
        'vendor': 'Pure-FTPd',
    },
    
    # SMTP Signatures
    r'^(\d{3})\s+([^\r\n]+mail[^\r\n]*)': {
        'service': 'SMTP',
        'category': ServiceCategory.MAIL_SERVER,
    },
    r'(Postfix)': {
        'service': 'Postfix',
        'category': ServiceCategory.MAIL_SERVER,
        'vendor': 'Postfix',
    },
    r'(Exim)[\s/]?([\d.]+)?': {
        'service': 'Exim',
        'category': ServiceCategory.MAIL_SERVER,
        'version_group': 2,
        'vendor': 'Exim',
    },
    r'(Sendmail)[\s/]?([\d.]+)?': {
        'service': 'Sendmail',
        'category': ServiceCategory.MAIL_SERVER,
        'version_group': 2,
        'vendor': 'Sendmail',
    },
    r'(Microsoft)\s*(Exchange)': {
        'service': 'Microsoft Exchange',
        'category': ServiceCategory.MAIL_SERVER,
        'vendor': 'Microsoft',
    },
    
    # Database Signatures
    r'(MySQL)[\s-]?([\d.]+)?': {
        'service': 'MySQL',
        'category': ServiceCategory.DATABASE,
        'version_group': 2,
        'vendor': 'Oracle',
        'cpe_template': 'a:oracle:mysql:{version}',
    },
    r'(MariaDB)[\s/]?([\d.]+)?': {
        'service': 'MariaDB',
        'category': ServiceCategory.DATABASE,
        'version_group': 2,
        'vendor': 'MariaDB',
        'cpe_template': 'a:mariadb:mariadb:{version}',
    },
    r'(PostgreSQL)[\s/]?([\d.]+)?': {
        'service': 'PostgreSQL',
        'category': ServiceCategory.DATABASE,
        'version_group': 2,
        'vendor': 'PostgreSQL',
        'cpe_template': 'a:postgresql:postgresql:{version}',
    },
    r'(MongoDB)[\s/]?([\d.]+)?': {
        'service': 'MongoDB',
        'category': ServiceCategory.DATABASE,
        'version_group': 2,
        'vendor': 'MongoDB',
        'cpe_template': 'a:mongodb:mongodb:{version}',
    },
    r'(Microsoft SQL Server)[\s/]?([\d.]+)?': {
        'service': 'MSSQL',
        'category': ServiceCategory.DATABASE,
        'version_group': 2,
        'vendor': 'Microsoft',
        'cpe_template': 'a:microsoft:sql_server:{version}',
    },
    r'(Redis)[\s/]?([\d.]+)?': {
        'service': 'Redis',
        'category': ServiceCategory.DATABASE,
        'version_group': 2,
        'vendor': 'Redis',
        'cpe_template': 'a:redis:redis:{version}',
    },
    
    # VNC
    r'RFB\s*([\d.]+)': {
        'service': 'VNC',
        'category': ServiceCategory.REMOTE_ACCESS,
        'version_group': 1,
        'vendor': 'VNC',
    },
    
    # Telnet
    r'(login|username|password).*:': {
        'service': 'Telnet',
        'category': ServiceCategory.REMOTE_ACCESS,
    },
    
    # RDP
    r'Remote Desktop Protocol': {
        'service': 'RDP',
        'category': ServiceCategory.REMOTE_ACCESS,
        'vendor': 'Microsoft',
    },
    
    # DNS
    r'(BIND)[\s/]?([\d.]+)?': {
        'service': 'BIND DNS',
        'category': ServiceCategory.DNS,
        'version_group': 2,
        'vendor': 'ISC',
    },
    r'(PowerDNS)[\s/]?([\d.]+)?': {
        'service': 'PowerDNS',
        'category': ServiceCategory.DNS,
        'version_group': 2,
        'vendor': 'PowerDNS',
    },
    
    # Proxy/Cache
    r'(Squid)[\s/]?([\d.]+)?': {
        'service': 'Squid Proxy',
        'category': ServiceCategory.PROXY,
        'version_group': 2,
        'vendor': 'Squid',
    },
    r'(HAProxy)[\s/]?([\d.]+)?': {
        'service': 'HAProxy',
        'category': ServiceCategory.PROXY,
        'version_group': 2,
        'vendor': 'HAProxy',
    },
    r'(Varnish)[\s/]?([\d.]+)?': {
        'service': 'Varnish Cache',
        'category': ServiceCategory.PROXY,
        'version_group': 2,
        'vendor': 'Varnish',
    },
    
    # VPN
    r'(OpenVPN)[\s/]?([\d.]+)?': {
        'service': 'OpenVPN',
        'category': ServiceCategory.VPN,
        'version_group': 2,
        'vendor': 'OpenVPN',
    },
    r'(Cisco)\s*(VPN|ASA)': {
        'service': 'Cisco VPN',
        'category': ServiceCategory.VPN,
        'vendor': 'Cisco',
    },
    
    # Application Servers
    r'(Tomcat)[\s/]?([\d.]+)?': {
        'service': 'Apache Tomcat',
        'category': ServiceCategory.APPLICATION,
        'version_group': 2,
        'vendor': 'Apache',
    },
    r'(Jetty)[\s/]?([\d.]+)?': {
        'service': 'Jetty',
        'category': ServiceCategory.APPLICATION,
        'version_group': 2,
        'vendor': 'Eclipse',
    },
    r'(Node\.js|nodejs)[\s/]?([\d.]+)?': {
        'service': 'Node.js',
        'category': ServiceCategory.APPLICATION,
        'version_group': 2,
        'vendor': 'Node.js',
    },
    r'(PHP)[\s/]?([\d.]+)?': {
        'service': 'PHP',
        'category': ServiceCategory.APPLICATION,
        'version_group': 2,
        'vendor': 'PHP',
    },
    r'(Python)[\s/]?([\d.]+)?': {
        'service': 'Python HTTP',
        'category': ServiceCategory.APPLICATION,
        'version_group': 2,
        'vendor': 'Python',
    },
    
    # Elasticsearch
    r'(Elasticsearch)[\s/]?([\d.]+)?': {
        'service': 'Elasticsearch',
        'category': ServiceCategory.DATABASE,
        'version_group': 2,
        'vendor': 'Elastic',
    },
    
    # Docker/Kubernetes
    r'(Docker)[\s/]?([\d.]+)?': {
        'service': 'Docker',
        'category': ServiceCategory.APPLICATION,
        'version_group': 2,
        'vendor': 'Docker',
    },
}

# Known vulnerability patterns (for educational purposes)
VULNERABILITY_PATTERNS = {
    # OpenSSH vulnerabilities
    r'OpenSSH_([1-6]\.\d)': ['CVE-2016-0777', 'CVE-2016-0778'],
    r'OpenSSH_([1-5]\.\d)': ['CVE-2014-2532', 'Multiple legacy vulnerabilities'],
    
    # Apache vulnerabilities  
    r'Apache/[12]\.[0-2]': ['Multiple legacy vulnerabilities'],
    r'Apache/2\.2': ['CVE-2017-7679', 'CVE-2017-9798'],
    
    # OpenSSL
    r'OpenSSL/1\.0\.1[abcdef]?': ['CVE-2014-0160 (Heartbleed)'],
    
    # vsftpd
    r'vsftpd-?2\.3\.4': ['CVE-2011-2523 (Backdoor)'],
    
    # SMB
    r'SMB.*1\.0': ['CVE-2017-0143 (EternalBlue)', 'MS17-010'],
}


class BannerDatabase:
    """
    Banner Fingerprinting Database.
    
    Provides:
    - Service identification from banners
    - Version detection
    - Vulnerability correlation
    - CPE generation
    """
    
    def __init__(self, custom_signatures: Optional[Dict] = None):
        """
        Initialize banner database.
        
        Args:
            custom_signatures: Optional additional signatures
        """
        self.signatures = BANNER_SIGNATURES.copy()
        self.vulnerability_patterns = VULNERABILITY_PATTERNS.copy()
        
        if custom_signatures:
            self.signatures.update(custom_signatures)
    
    def analyze(self, banner: str) -> List[ServiceFingerprint]:
        """
        Analyze banner and return possible fingerprints.
        
        Args:
            banner: Raw banner string
            
        Returns:
            List of possible service fingerprints
        """
        if not banner:
            return []
        
        results = []
        banner_clean = banner.strip()
        
        # Try each signature pattern
        for pattern, info in self.signatures.items():
            match = re.search(pattern, banner_clean, re.IGNORECASE | re.MULTILINE)
            
            if match:
                # Extract version
                version = None
                if 'version_group' in info and info['version_group'] <= len(match.groups()):
                    version = match.group(info['version_group'])
                    if version:
                        version = version.strip()
                
                # Extract vendor
                vendor = info.get('vendor', '')
                if 'vendor_extract' in info:
                    vendor_match = re.search(info['vendor_extract'], banner_clean, re.IGNORECASE)
                    if vendor_match:
                        vendor = vendor_match.group(1)
                
                # Generate CPE
                cpe = None
                if 'cpe_template' in info:
                    cpe = info['cpe_template'].format(
                        vendor=vendor or 'unknown',
                        version=version or '*'
                    )
                
                # Check for known vulnerabilities
                vulns = self._check_vulnerabilities(banner_clean)
                
                fingerprint = ServiceFingerprint(
                    service_name=info['service'],
                    version=version,
                    category=info['category'],
                    vendor=vendor or None,
                    cpe=cpe,
                    confidence=85 if version else 70,
                    vulnerabilities=vulns,
                    additional_info={
                        'raw_banner': banner_clean[:200],
                        'matched_pattern': pattern
                    }
                )
                
                results.append(fingerprint)
        
        # Sort by confidence
        results.sort(key=lambda x: x.confidence, reverse=True)
        
        return results
    
    def _check_vulnerabilities(self, banner: str) -> List[str]:
        """Check banner against known vulnerability patterns"""
        vulns = []
        
        for pattern, cve_list in self.vulnerability_patterns.items():
            if re.search(pattern, banner, re.IGNORECASE):
                vulns.extend(cve_list)
        
        return vulns
    
    def get_service_info(self, port: int, banner: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive service information.
        
        Args:
            port: Port number
            banner: Optional banner string
            
        Returns:
            Dictionary with service information
        """
        info = {
            'port': port,
            'service': 'Unknown',
            'version': None,
            'category': ServiceCategory.UNKNOWN,
            'fingerprints': [],
            'vulnerabilities': []
        }
        
        if banner:
            fingerprints = self.analyze(banner)
            if fingerprints:
                info['fingerprints'] = fingerprints
                info['service'] = fingerprints[0].service_name
                info['version'] = fingerprints[0].version
                info['category'] = fingerprints[0].category
                info['vulnerabilities'] = fingerprints[0].vulnerabilities
        
        return info
    
    def add_signature(self, pattern: str, info: Dict) -> None:
        """Add a custom signature"""
        self.signatures[pattern] = info
    
    def add_vulnerability_pattern(self, pattern: str, cves: List[str]) -> None:
        """Add a vulnerability pattern"""
        self.vulnerability_patterns[pattern] = cves
    
    def print_analysis(self, banner: str) -> None:
        """Print detailed banner analysis"""
        fingerprints = self.analyze(banner)
        
        try:
            from colorama import Fore, Style
        except:
            Fore = type('', (), {'CYAN': '\033[96m', 'GREEN': '\033[92m',
                                 'YELLOW': '\033[93m', 'RED': '\033[91m',
                                 'RESET': '\033[0m'})()
            Style = type('', (), {'RESET_ALL': '\033[0m'})()
        
        print(f"\n{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}BANNER ANALYSIS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}Raw Banner:{Style.RESET_ALL}")
        print(f"  {banner[:200]}")
        
        if fingerprints:
            for fp in fingerprints:
                print(f"\n{Fore.GREEN}● {fp.service_name}{Style.RESET_ALL}")
                if fp.version:
                    print(f"  Version: {fp.version}")
                print(f"  Category: {fp.category.value}")
                if fp.vendor:
                    print(f"  Vendor: {fp.vendor}")
                if fp.cpe:
                    print(f"  CPE: {fp.cpe}")
                print(f"  Confidence: {fp.confidence}%")
                
                if fp.vulnerabilities:
                    print(f"\n  {Fore.RED}Potential Vulnerabilities:{Style.RESET_ALL}")
                    for vuln in fp.vulnerabilities:
                        print(f"    {Fore.RED}! {vuln}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[i] No matching signatures found{Style.RESET_ALL}")
