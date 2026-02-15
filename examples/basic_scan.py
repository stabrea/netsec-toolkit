#!/usr/bin/env python3
"""
Basic Port Scan Example
=======================

Demonstrates how to use the PortScanner class to scan localhost for
common open ports and print the results.

DISCLAIMER: Only scan hosts you own or have explicit authorization to test.

Usage:
    python examples/basic_scan.py
"""

from netsec_toolkit.port_scanner import PortScanner, PortState


def main() -> None:
    # Create a scanner targeting localhost with a 1-second timeout
    scanner = PortScanner(target="127.0.0.1", timeout=1.0, grab_banners=True)

    # Scan a handful of common ports
    print("Scanning localhost for common ports...")
    result = scanner.scan(ports=[22, 80, 443, 3000, 5432, 8080, 8443])

    # Print summary
    print(f"\nTarget:    {result.target} ({result.resolved_ip})")
    print(f"Duration:  {result.duration_seconds}s")
    print(f"Scanned:   {len(result.ports)} ports")
    print(f"Open:      {len(result.open_ports)} ports\n")

    # Print details for each port
    for port_result in result.ports:
        state_label = port_result.state.value.upper()
        line = f"  Port {port_result.port:>5}  [{state_label:>8}]  {port_result.service}"
        if port_result.banner:
            line += f"  -- {port_result.banner[:60]}"
        print(line)

    # Show only open ports as a dict (useful for JSON output)
    if result.open_ports:
        print("\nOpen port details:")
        for p in result.open_ports:
            print(f"  {p.to_dict()}")
    else:
        print("\nNo open ports found on localhost.")


if __name__ == "__main__":
    main()
