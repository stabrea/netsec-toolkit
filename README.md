# netsec-toolkit

```
                 _                       _              _ _    _ _
  _ __   ___| |_ ___  ___  ___      | |_ ___   ___ | | | _(_) |_
 | '_ \ / _ \ __/ __|/ _ \/ __|_____| __/ _ \ / _ \| | |/ / | __|
 | | | |  __/ |_\__ \  __/ (_|______| || (_) | (_) | |   <| | |_
 |_| |_|\___|\__|___/\___|\___|      \__\___/ \___/|_|_|\_\_|\__|

         Network Security Scanning Toolkit v1.0.0
```

A comprehensive, modular network security toolkit built in Python for authorized penetration testing, network reconnaissance, and security posture assessment. Designed for cybersecurity students and professionals who need a lightweight, dependency-minimal scanning solution.

## Features

### Port Scanner
- **TCP connect scanning** with configurable thread concurrency (up to 65,535 ports)
- **Service detection** via well-known port mapping (80+ services)
- **Banner grabbing** with protocol-aware probes (HTTP, SSH, FTP, SMTP)
- **SSL/TLS probing** with certificate inspection on encrypted ports
- **Scan profiles**: Top 20, Top 100, or full 1-65535 range
- Custom port lists and ranges (`22,80,443` or `1-1024`)

### Network Mapper
- **ICMP ping sweep** for fast host discovery across subnets
- **TCP fallback probing** when ICMP is blocked
- **ARP table parsing** for MAC address resolution
- **OS fingerprinting** via TTL analysis and port signatures
- **Reverse DNS** hostname resolution
- **Auto-detection** of local subnet when no target specified

### Vulnerability Checker
- **Sensitive port detection** (databases, RDP, SMB, Telnet, etc.)
- **SSH configuration analysis** (protocol version, software disclosure)
- **SSL/TLS assessment** (deprecated protocols, weak ciphers, certificate validity)
- **HTTP security headers** audit (HSTS, CSP, X-Frame-Options, etc.)
- **DNS zone transfer** testing
- **Cookie security** flag verification
- Severity-ranked findings (Critical / High / Medium / Low / Info)

### Report Generator
- **JSON output** for programmatic consumption and CI/CD integration
- **HTML reports** with dark-themed UI, severity badges, and executive summaries
- Self-contained HTML (inline CSS, no external dependencies)
- Combined multi-scan reports

## Installation

### Prerequisites
- Python 3.10 or later
- pip package manager

### Quick Start

```bash
# Clone the repository
git clone https://github.com/taofikbishi/netsec-toolkit.git
cd netsec-toolkit

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

### Verify Installation

```bash
python main.py --version
# netsec-toolkit v1.0.0
```

## Usage

### Port Scanning

```bash
# Scan top 20 common ports
python main.py scan 192.168.1.1

# Scan specific ports
python main.py scan 192.168.1.1 -p 22,80,443,8080

# Scan a port range
python main.py scan 192.168.1.1 -p 1-1024

# Scan top 100 ports with faster timeout
python main.py scan example.com --profile top100 -t 1.0

# Scan all 65535 ports (takes longer)
python main.py scan 10.0.0.1 --profile all --threads 200

# Save results to file
python main.py scan 192.168.1.1 -p 22,80,443 -o scan_results
```

### Network Mapping

```bash
# Auto-detect and scan local subnet
python main.py map

# Scan a specific subnet
python main.py map 192.168.1.0/24

# Scan with custom timeout and save report
python main.py map 10.0.0.0/24 -t 1.0 -o network_map
```

### Vulnerability Assessment

```bash
# Run all vulnerability checks
python main.py vuln 192.168.1.1

# Check a web server
python main.py vuln example.com -o vuln_report

# Use a longer timeout for slow targets
python main.py vuln 10.0.0.1 -t 5.0
```

### Full Assessment

```bash
# Complete scan + vulnerability assessment with reports
python main.py full 192.168.1.1

# Full assessment with HTML report only
python main.py full example.com -o assessment --format html

# Full assessment with custom ports
python main.py full 10.0.0.1 -p 22,80,443,3306,8080 -o full_report
```

### Quiet Mode

```bash
# Suppress the banner for scripting
python main.py -q scan 192.168.1.1
```

## Screenshots

> Screenshots will be added after initial release. The tool produces:
> - Rich terminal output with colored tables and progress indicators
> - Dark-themed HTML reports with severity badges and executive summaries
> - JSON reports for automated processing

## Architecture

```
netsec-toolkit/
|-- main.py                        # Entry point
|-- setup.py                       # Package configuration
|-- requirements.txt               # Dependencies (only: rich)
|-- netsec_toolkit/
|   |-- __init__.py                # Package init, version, public API
|   |-- port_scanner.py            # TCP connect scanner + banner grabbing
|   |-- network_mapper.py          # Subnet discovery + OS fingerprinting
|   |-- vuln_checker.py            # Security misconfiguration checks
|   |-- report_generator.py        # JSON + HTML report generation
|   |-- cli.py                     # argparse CLI with subcommands
```

### Design Principles

- **Minimal dependencies**: Core scanning uses only Python stdlib (`socket`, `ssl`, `ipaddress`, `struct`, `http.client`). The only external package is `rich` for terminal formatting.
- **Modular architecture**: Each scanner is an independent class that can be used programmatically or via CLI.
- **Type-safe**: Full type hints throughout, compatible with mypy strict mode.
- **Dataclass results**: All scan results use `@dataclass` with `.to_dict()` serialization for clean data flow.
- **Concurrent scanning**: Thread pools for port scanning and host discovery with configurable parallelism.
- **Graceful degradation**: Rich terminal output when available, plain text fallback otherwise.

### How It Works

1. **Port Scanner**: Opens TCP connections (full 3-way handshake) to each target port. Open ports are probed for service banners and SSL/TLS metadata. This is a "connect scan" -- visible to IDS but requires no root privileges.

2. **Network Mapper**: Sends ICMP echo requests via the system `ping` command, with TCP fallback for hosts that block ICMP. Correlates results with the ARP cache for MAC addresses and uses TTL values for OS fingerprinting.

3. **Vulnerability Checker**: Connects to discovered services and analyzes responses against known security baselines (deprecated TLS versions, missing HTTP headers, exposed sensitive ports, etc.).

4. **Report Generator**: Aggregates all results into structured JSON and self-contained HTML with severity-coded findings and remediation guidance.

## Ethical Use Disclaimer

**This tool is intended for authorized security testing and educational purposes only.**

- Always obtain **explicit written permission** before scanning any network or system you do not own.
- Unauthorized port scanning, network reconnaissance, and vulnerability testing is **illegal** in most jurisdictions under laws such as the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and similar legislation worldwide.
- The authors of this tool assume **no liability** for any misuse or damage caused by this software.
- Use this tool **responsibly** and in accordance with all applicable laws and regulations.
- When in doubt, **do not scan**. Ask for permission first.

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Write clean, typed, well-documented code
4. Test against authorized targets only
5. Submit a pull request

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

Built by [Taofik Bishi](https://github.com/taofikbishi) for educational and authorized security testing purposes.
