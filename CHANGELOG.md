# Changelog

All notable changes to ShadowScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-01-15

### Added
- Initial release of ShadowScan
- Multi-threaded port scanning with configurable thread count
- French navigation interface (Navigation France)
- Quick scan mode for common ports (24 ports)
- Full scan mode for all 65,535 TCP ports
- Custom port range scanning
- Service detection with predefined service database
- Banner grabbing capability
- Color-coded terminal output with cross-platform support
- JSON and TXT export functionality
- Interactive mode with menu-driven interface
- Comprehensive documentation (README, CONTRIBUTING)
- Shadow Public License v1.0
- Setup configuration for pip installation

### Features
- **Quick Scan**: Scans 24 most common ports (FTP, SSH, HTTP, HTTPS, etc.)
- **Full Scan**: Complete port enumeration (1-65535)
- **Custom Scan**: User-defined port ranges or specific ports
- **Banner Grabbing**: Extract service banners for fingerprinting
- **Service Detection**: Automatic identification of services on open ports
- **Export Results**: Save scan results in JSON or plain text format
- **French Interface**: Bilingual support with French navigation menu

### Security
- Disclaimer and usage warnings for ethical use only
- License restrictions against malicious use
- Comprehensive legal documentation

## [1.0.0] - 2023-12-01 (Development Version)

### Added
- Basic port scanning functionality
- Simple command-line interface
- Basic output formatting

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 2.0.0 | 2024-01-15 | Initial public release |
| 1.0.0 | 2023-12-01 | Development version |

---

## Future Roadmap

### Planned Features (v2.1.0)
- [ ] UDP port scanning support
- [ ] SYN scanning (stealth scan)
- [ ] OS fingerprinting
- [ ] Network discovery (host discovery)
- [ ] IPv6 support

### Planned Features (v2.2.0)
- [ ] GUI interface
- [ ] Web-based dashboard
- [ ] Database integration for scan history
- [ ] Scheduled scanning

### Planned Features (v3.0.0)
- [ ] Plugin system for custom scanners
- [ ] API for integration with other tools
- [ ] Cloud-based scanning capabilities

---

*This changelog is maintained by Meheraz HOSEN SIAM*
