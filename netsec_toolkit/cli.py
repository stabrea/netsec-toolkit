"""
CLI Interface Module

Provides a professional command-line interface for the netsec-toolkit
using argparse with subcommands for each scanning capability.

Subcommands:
    scan    - TCP port scanning
    map     - Network host discovery
    vuln    - Vulnerability assessment
    full    - Complete assessment (scan + map + vuln + report)

Usage:
    netsec scan 192.168.1.1 --ports 22,80,443
    netsec map 192.168.1.0/24
    netsec vuln example.com --output report
    netsec full 192.168.1.1 --format html
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import NoReturn

# Rich is the only external dependency - used for terminal formatting
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from netsec_toolkit import __version__
from netsec_toolkit.port_scanner import PortScanner, PortState
from netsec_toolkit.network_mapper import NetworkMapper
from netsec_toolkit.vuln_checker import VulnerabilityChecker, Severity
from netsec_toolkit.report_generator import ReportGenerator


# ASCII banner displayed at startup
BANNER = r"""
                 _                       _              _ _    _ _
  _ __   ___| |_ ___  ___  ___      | |_ ___   ___ | | | _(_) |_
 | '_ \ / _ \ __/ __|/ _ \/ __|_____| __/ _ \ / _ \| | |/ / | __|
 | | | |  __/ |_\__ \  __/ (_|______| || (_) | (_) | |   <| | |_
 |_| |_|\___|\__|___/\___|\___|      \__\___/ \___/|_|_|\_\_|\__|
"""

DISCLAIMER = (
    "[bold red]DISCLAIMER:[/bold red] This tool is for authorized security "
    "testing only.\nUnauthorized scanning of networks you do not own or "
    "have explicit written\npermission to test is illegal. "
    "Use responsibly."
    if RICH_AVAILABLE else
    "DISCLAIMER: This tool is for authorized security testing only.\n"
    "Unauthorized scanning of networks you do not own or have explicit "
    "written\npermission to test is illegal. Use responsibly."
)


def get_console() -> Console | None:
    """Get a Rich console instance if available."""
    return Console(stderr=True) if RICH_AVAILABLE else None


def print_banner() -> None:
    """Print the application banner and disclaimer."""
    console = get_console()
    if console:
        console.print(
            Panel(
                f"[bold cyan]{BANNER}[/bold cyan]\n"
                f"[dim]v{__version__} | Network Security Toolkit[/dim]",
                border_style="cyan",
                padding=(0, 2),
            )
        )
        console.print(f"\n{DISCLAIMER}\n")
    else:
        print(BANNER)
        print(f"v{__version__} | Network Security Toolkit")
        print(f"\n{DISCLAIMER}\n")


def severity_color(severity: Severity) -> str:
    """Map severity level to Rich color string."""
    match severity:
        case Severity.CRITICAL:
            return "bold red"
        case Severity.HIGH:
            return "red"
        case Severity.MEDIUM:
            return "yellow"
        case Severity.LOW:
            return "blue"
        case Severity.INFO:
            return "dim"


def build_parser() -> argparse.ArgumentParser:
    """
    Construct the complete CLI argument parser with all subcommands.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="netsec",
        description="netsec-toolkit: Network Security Scanning Toolkit",
        epilog=(
            "DISCLAIMER: Authorized testing only. "
            "See --help on each subcommand for details."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"netsec-toolkit v{__version__}",
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and verbose output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # === SCAN subcommand ===
    scan_parser = subparsers.add_parser(
        "scan",
        help="TCP port scan a target host",
        description="Scan target for open TCP ports with service detection.",
    )
    scan_parser.add_argument(
        "target",
        help="Target hostname or IP address",
    )
    scan_parser.add_argument(
        "-p", "--ports",
        type=str,
        default=None,
        help=(
            "Comma-separated ports or range (e.g., '22,80,443' or '1-1024'). "
            "Default: top 20 common ports"
        ),
    )
    scan_parser.add_argument(
        "--profile",
        choices=["top20", "top100", "all"],
        default="top20",
        help="Predefined port list profile (default: top20)",
    )
    scan_parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Connection timeout per port in seconds (default: 2.0)",
    )
    scan_parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Max concurrent scanning threads (default: 100)",
    )
    scan_parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable banner grabbing",
    )
    scan_parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path (without extension). Generates .json and .html",
    )

    # === MAP subcommand ===
    map_parser = subparsers.add_parser(
        "map",
        help="Discover hosts on a network subnet",
        description="Map live hosts on a subnet with OS fingerprinting.",
    )
    map_parser.add_argument(
        "subnet",
        nargs="?",
        default=None,
        help="Subnet in CIDR notation (e.g., 192.168.1.0/24). Auto-detects if omitted.",
    )
    map_parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Ping timeout per host in seconds (default: 2.0)",
    )
    map_parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Max concurrent threads (default: 50)",
    )
    map_parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path (without extension)",
    )

    # === VULN subcommand ===
    vuln_parser = subparsers.add_parser(
        "vuln",
        help="Run vulnerability checks against a target",
        description="Assess target for common security misconfigurations.",
    )
    vuln_parser.add_argument(
        "target",
        help="Target hostname or IP address",
    )
    vuln_parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=3.0,
        help="Connection timeout in seconds (default: 3.0)",
    )
    vuln_parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path (without extension)",
    )

    # === FULL subcommand ===
    full_parser = subparsers.add_parser(
        "full",
        help="Run complete assessment (scan + vuln + report)",
        description="Comprehensive security assessment with full reporting.",
    )
    full_parser.add_argument(
        "target",
        help="Target hostname or IP address",
    )
    full_parser.add_argument(
        "-p", "--ports",
        type=str,
        default=None,
        help="Comma-separated ports or range",
    )
    full_parser.add_argument(
        "--profile",
        choices=["top20", "top100", "all"],
        default="top20",
        help="Port scan profile (default: top20)",
    )
    full_parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=2.0,
        help="Connection timeout in seconds (default: 2.0)",
    )
    full_parser.add_argument(
        "-o", "--output",
        type=str,
        default="netsec_report",
        help="Output file base name (default: netsec_report)",
    )
    full_parser.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Report format (default: both)",
    )

    return parser


def parse_ports(port_string: str) -> list[int]:
    """
    Parse a port specification string into a list of port numbers.

    Supports comma-separated values, ranges, and combinations:
        "22,80,443"     -> [22, 80, 443]
        "1-100"         -> [1, 2, ..., 100]
        "22,80,100-110" -> [22, 80, 100, 101, ..., 110]

    Args:
        port_string: Port specification string.

    Returns:
        Sorted list of unique port numbers.
    """
    ports: set[int] = set()

    for part in port_string.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_port = int(start)
                end_port = int(end)
                if 1 <= start_port <= 65535 and 1 <= end_port <= 65535:
                    ports.update(range(start_port, end_port + 1))
            except ValueError:
                print(f"Warning: Invalid port range '{part}', skipping.")
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                print(f"Warning: Invalid port '{part}', skipping.")

    return sorted(ports)


def cmd_scan(args: argparse.Namespace) -> None:
    """Execute the port scan subcommand."""
    console = get_console()

    # Parse port specification
    ports = parse_ports(args.ports) if args.ports else None

    scanner = PortScanner(
        target=args.target,
        timeout=args.timeout,
        max_threads=args.threads,
        grab_banners=not args.no_banner,
    )

    if console and RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("[bold]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"Scanning {args.target}...", total=None
            )
            result = scanner.scan(ports=ports, profile=args.profile)
            progress.update(task, completed=100, total=100)
    else:
        print(f"Scanning {args.target}...")
        result = scanner.scan(ports=ports, profile=args.profile)

    # Display results
    if console and RICH_AVAILABLE:
        table = Table(
            title=f"Scan Results: {result.target} ({result.resolved_ip})",
            box=box.ROUNDED,
            border_style="cyan",
            show_lines=False,
        )
        table.add_column("Port", style="bold", width=8)
        table.add_column("State", width=10)
        table.add_column("Service", width=15)
        table.add_column("Banner", max_width=50)
        table.add_column("Time", width=10, justify="right")

        for port_result in result.ports:
            if port_result.state == PortState.OPEN:
                state_str = "[bold green]open[/bold green]"
            elif port_result.state == PortState.FILTERED:
                state_str = "[yellow]filtered[/yellow]"
            else:
                continue  # Skip closed ports in display

            banner = port_result.banner[:50] if port_result.banner else "-"
            table.add_row(
                str(port_result.port),
                state_str,
                port_result.service,
                banner,
                f"{port_result.response_time_ms:.1f}ms",
            )

        console.print(table)
        console.print(
            f"\n[dim]Scanned {len(result.ports)} ports in "
            f"{result.duration_seconds}s | "
            f"{len(result.open_ports)} open[/dim]"
        )
    else:
        print(f"\nResults for {result.target} ({result.resolved_ip}):")
        print(f"{'Port':<8} {'State':<10} {'Service':<15} {'Banner':<40}")
        print("-" * 73)
        for port_result in result.ports:
            if port_result.state != PortState.CLOSED:
                banner = port_result.banner[:40] if port_result.banner else "-"
                print(
                    f"{port_result.port:<8} "
                    f"{port_result.state.value:<10} "
                    f"{port_result.service:<15} "
                    f"{banner:<40}"
                )
        print(
            f"\nScanned {len(result.ports)} ports in "
            f"{result.duration_seconds}s | "
            f"{len(result.open_ports)} open"
        )

    # Generate reports if output specified
    if args.output:
        report = ReportGenerator(title=f"Port Scan: {args.target}")
        report.add_port_scan(result)
        json_path = report.generate_json(f"{args.output}.json")
        html_path = report.generate_html(f"{args.output}.html")
        if console:
            console.print(f"\n[green]Reports saved:[/green]")
            console.print(f"  JSON: {json_path}")
            console.print(f"  HTML: {html_path}")
        else:
            print(f"\nReports saved:\n  JSON: {json_path}\n  HTML: {html_path}")


def cmd_map(args: argparse.Namespace) -> None:
    """Execute the network mapping subcommand."""
    console = get_console()

    subnet = args.subnet
    if subnet is None:
        subnet = NetworkMapper.get_local_subnet()
        if console:
            console.print(f"[cyan]Auto-detected subnet:[/cyan] {subnet}")
        else:
            print(f"Auto-detected subnet: {subnet}")

    mapper = NetworkMapper(
        subnet=subnet,
        timeout=args.timeout,
        max_threads=args.threads,
    )

    if console and RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Mapping {subnet}...", total=None)
            result = mapper.discover()
            progress.update(task, completed=100, total=100)
    else:
        print(f"Mapping {subnet}...")
        result = mapper.discover()

    # Display results
    alive = result.alive_hosts
    if console and RICH_AVAILABLE:
        table = Table(
            title=f"Network Map: {result.subnet}",
            box=box.ROUNDED,
            border_style="cyan",
        )
        table.add_column("IP Address", style="bold green")
        table.add_column("Hostname")
        table.add_column("OS Hint")
        table.add_column("MAC Address", style="dim")
        table.add_column("Open Ports")
        table.add_column("Response", justify="right")

        for host in alive:
            ports_str = ", ".join(str(p) for p in host.open_ports) or "-"
            table.add_row(
                host.ip,
                host.hostname or "-",
                host.os_hint or "-",
                host.mac_address or "-",
                ports_str,
                f"{host.response_time_ms:.1f}ms",
            )

        console.print(table)
        console.print(
            f"\n[dim]{len(alive)} hosts alive out of "
            f"{len(result.hosts)} scanned in "
            f"{result.duration_seconds}s[/dim]"
        )
    else:
        print(f"\nNetwork Map: {result.subnet}")
        print(f"{'IP':<16} {'Hostname':<25} {'OS Hint':<30} {'Ports':<15}")
        print("-" * 86)
        for host in alive:
            ports_str = ", ".join(str(p) for p in host.open_ports) or "-"
            print(
                f"{host.ip:<16} "
                f"{(host.hostname or '-'):<25} "
                f"{(host.os_hint or '-'):<30} "
                f"{ports_str:<15}"
            )
        print(f"\n{len(alive)} hosts alive / {len(result.hosts)} scanned")

    if args.output:
        report = ReportGenerator(title=f"Network Map: {result.subnet}")
        report.add_network_map(result)
        json_path = report.generate_json(f"{args.output}.json")
        html_path = report.generate_html(f"{args.output}.html")
        if console:
            console.print(f"\n[green]Reports saved:[/green]")
            console.print(f"  JSON: {json_path}")
            console.print(f"  HTML: {html_path}")
        else:
            print(f"\nReports saved:\n  JSON: {json_path}\n  HTML: {html_path}")


def cmd_vuln(args: argparse.Namespace) -> None:
    """Execute the vulnerability check subcommand."""
    console = get_console()

    checker = VulnerabilityChecker(
        target=args.target,
        timeout=args.timeout,
    )

    if console and RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"Checking {args.target}...", total=None
            )
            result = checker.run_all_checks()
            progress.update(task, completed=100, total=100)
    else:
        print(f"Checking {args.target}...")
        result = checker.run_all_checks()

    # Display results
    if console and RICH_AVAILABLE:
        # Summary panel
        summary = (
            f"[bold]Target:[/bold] {result.target}\n"
            f"[bold]Duration:[/bold] {result.duration_seconds}s\n"
            f"[bold]Findings:[/bold] {len(result.findings)} total\n"
            f"  [bold red]Critical: {result.critical_count}[/bold red] | "
            f"[red]High: {result.high_count}[/red] | "
            f"[yellow]Medium: {result.medium_count}[/yellow] | "
            f"[blue]Low: {result.low_count}[/blue] | "
            f"[dim]Info: {result.info_count}[/dim]"
        )
        console.print(Panel(summary, title="Vulnerability Assessment", border_style="cyan"))

        # Individual findings
        for finding in result.findings:
            color = severity_color(finding.severity)
            port_info = f" (port {finding.port})" if finding.port else ""

            console.print(
                f"\n[{color}][{finding.severity.value.upper()}][/{color}] "
                f"[bold]{finding.title}[/bold]{port_info}"
            )
            console.print(f"  {finding.description}")
            if finding.remediation:
                console.print(f"  [dim]Fix: {finding.remediation}[/dim]")
    else:
        print(f"\nVulnerability Assessment: {result.target}")
        print(f"Duration: {result.duration_seconds}s | Findings: {len(result.findings)}")
        print("-" * 60)
        for finding in result.findings:
            port_info = f" (port {finding.port})" if finding.port else ""
            print(f"\n[{finding.severity.value.upper()}] {finding.title}{port_info}")
            print(f"  {finding.description}")
            if finding.remediation:
                print(f"  Fix: {finding.remediation}")

    if args.output:
        report = ReportGenerator(title=f"Vulnerability Assessment: {args.target}")
        report.add_vuln_report(result)
        json_path = report.generate_json(f"{args.output}.json")
        html_path = report.generate_html(f"{args.output}.html")
        if console:
            console.print(f"\n[green]Reports saved:[/green]")
            console.print(f"  JSON: {json_path}")
            console.print(f"  HTML: {html_path}")
        else:
            print(f"\nReports saved:\n  JSON: {json_path}\n  HTML: {html_path}")


def cmd_full(args: argparse.Namespace) -> None:
    """Execute the full assessment subcommand (scan + vuln + report)."""
    console = get_console()

    ports = parse_ports(args.ports) if args.ports else None
    report = ReportGenerator(
        title=f"Full Security Assessment: {args.target}",
        author="netsec-toolkit automated scan",
    )

    # Step 1: Port scan
    if console:
        console.print("\n[bold cyan]Phase 1/2:[/bold cyan] Port Scanning")
    else:
        print("\nPhase 1/2: Port Scanning")

    scanner = PortScanner(target=args.target, timeout=args.timeout)
    scan_result = scanner.scan(ports=ports, profile=args.profile)
    report.add_port_scan(scan_result)

    if console:
        console.print(
            f"  Found [green]{len(scan_result.open_ports)}[/green] open ports "
            f"in {scan_result.duration_seconds}s"
        )
    else:
        print(f"  Found {len(scan_result.open_ports)} open ports")

    # Step 2: Vulnerability check
    if console:
        console.print("\n[bold cyan]Phase 2/2:[/bold cyan] Vulnerability Assessment")
    else:
        print("\nPhase 2/2: Vulnerability Assessment")

    checker = VulnerabilityChecker(target=args.target, timeout=args.timeout)
    vuln_result = checker.run_all_checks()
    report.add_vuln_report(vuln_result)

    if console:
        console.print(
            f"  Found [yellow]{len(vuln_result.findings)}[/yellow] findings "
            f"({vuln_result.critical_count} critical, {vuln_result.high_count} high)"
        )
    else:
        print(f"  Found {len(vuln_result.findings)} findings")

    # Step 3: Generate reports
    if console:
        console.print("\n[bold cyan]Generating reports...[/bold cyan]")
    else:
        print("\nGenerating reports...")

    output_base = args.output

    match args.format:
        case "json":
            json_path = report.generate_json(f"{output_base}.json")
            if console:
                console.print(f"  [green]JSON:[/green] {json_path}")
            else:
                print(f"  JSON: {json_path}")
        case "html":
            html_path = report.generate_html(f"{output_base}.html")
            if console:
                console.print(f"  [green]HTML:[/green] {html_path}")
            else:
                print(f"  HTML: {html_path}")
        case "both":
            json_path = report.generate_json(f"{output_base}.json")
            html_path = report.generate_html(f"{output_base}.html")
            if console:
                console.print(f"  [green]JSON:[/green] {json_path}")
                console.print(f"  [green]HTML:[/green] {html_path}")
            else:
                print(f"  JSON: {json_path}")
                print(f"  HTML: {html_path}")

    if console:
        console.print("\n[bold green]Assessment complete.[/bold green]")
    else:
        print("\nAssessment complete.")


def main(argv: list[str] | None = None) -> None:
    """
    Main CLI entry point.

    Args:
        argv: Command-line arguments (defaults to sys.argv).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.quiet:
        print_banner()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    match args.command:
        case "scan":
            cmd_scan(args)
        case "map":
            cmd_map(args)
        case "vuln":
            cmd_vuln(args)
        case "full":
            cmd_full(args)
        case _:
            parser.print_help()
            sys.exit(1)
