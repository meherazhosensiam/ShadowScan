#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShadowScan - Advanced Network Port Scanner
Author: Meheraz HOSEN SIAM
Description: A professional penetration testing tool for network reconnaissance
License: Shadow Public License v1.0

This is the main entry point that provides backward compatibility
and imports the modular components.
"""

# Import from modular package
from shadowscan import (
    TCPScanner, SYNScanner, UDPScanner,
    OSFingerprinter, BannerDatabase
)
from shadowscan.utils.output import OutputFormatter
from shadowscan.utils.network import NetworkUtils
from shadowscan.scanners.tcp_scan import quick_tcp_scan, full_tcp_scan
from shadowscan.scanners.syn_scan import quick_syn_scan
from shadowscan.scanners.udp_scan import quick_udp_scan

__version__ = "2.0.0"
__author__ = "Meheraz HOSEN SIAM"

# Re-export for backward compatibility
__all__ = [
    'TCPScanner', 'SYNScanner', 'UDPScanner',
    'OSFingerprinter', 'BannerDatabase',
    'OutputFormatter', 'NetworkUtils',
    'quick_tcp_scan', 'full_tcp_scan',
    'quick_syn_scan', 'quick_udp_scan'
]


def main():
    """Main entry point - delegates to package main"""
    from shadowscan.__main__ import main as _main
    _main()


if __name__ == "__main__":
    main()
