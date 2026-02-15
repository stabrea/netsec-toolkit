#!/usr/bin/env python3
"""
netsec-toolkit - Network Security Scanning Toolkit

Entry point for the netsec-toolkit CLI application.

DISCLAIMER: This tool is for authorized security testing and educational
purposes only. Unauthorized access to computer systems is illegal.
Always obtain written permission before scanning any network or host.

Usage:
    python main.py scan <target> [options]
    python main.py map [subnet] [options]
    python main.py vuln <target> [options]
    python main.py full <target> [options]

Examples:
    python main.py scan 192.168.1.1 -p 22,80,443
    python main.py scan example.com --profile top100
    python main.py map 192.168.1.0/24
    python main.py vuln example.com -o vuln_report
    python main.py full 192.168.1.1 -o full_report --format html
"""

import sys

from netsec_toolkit.cli import main


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except ConnectionError as exc:
        print(f"\nConnection error: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"\nUnexpected error: {exc}")
        sys.exit(1)
