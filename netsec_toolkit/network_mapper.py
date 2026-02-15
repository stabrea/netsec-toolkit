"""
Network Mapper Module

Discovers live hosts on a local subnet using ICMP ping sweeps and
ARP-based discovery. Performs basic OS fingerprinting based on TTL
values and open port signatures.

This module works with IPv4 networks and uses the ipaddress stdlib
module for subnet calculations.

Usage:
    mapper = NetworkMapper("192.168.1.0/24")
    hosts = mapper.discover()
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


# TTL-based OS fingerprinting heuristics.
# Different operating systems use characteristic default TTL values.
TTL_FINGERPRINTS: dict[range, str] = {
    range(0, 33): "Likely embedded device / unusual config",
    range(33, 65): "Likely Linux / Unix / Android",
    range(65, 129): "Likely Windows / macOS / iOS",
    range(129, 256): "Likely Solaris / AIX / network device",
}


@dataclass
class HostInfo:
    """Information about a discovered host on the network."""
    ip: str
    hostname: str = ""
    is_alive: bool = False
    ttl: int = 0
    os_hint: str = ""
    mac_address: str = ""
    response_time_ms: float = 0.0
    open_ports: list[int] = field(default_factory=list)
    discovery_method: str = ""

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON reporting."""
        result: dict = {
            "ip": self.ip,
            "is_alive": self.is_alive,
        }
        if self.hostname:
            result["hostname"] = self.hostname
        if self.ttl:
            result["ttl"] = self.ttl
        if self.os_hint:
            result["os_hint"] = self.os_hint
        if self.mac_address:
            result["mac_address"] = self.mac_address
        if self.response_time_ms > 0:
            result["response_time_ms"] = round(self.response_time_ms, 2)
        if self.open_ports:
            result["open_ports"] = self.open_ports
        if self.discovery_method:
            result["discovery_method"] = self.discovery_method
        return result


@dataclass
class NetworkMap:
    """Complete map of discovered network hosts."""
    subnet: str
    scan_start: float
    scan_end: float = 0.0
    hosts: list[HostInfo] = field(default_factory=list)

    @property
    def alive_hosts(self) -> list[HostInfo]:
        """Return only hosts that responded to probes."""
        return [h for h in self.hosts if h.is_alive]

    @property
    def duration_seconds(self) -> float:
        """Total scan duration in seconds."""
        return round(self.scan_end - self.scan_start, 2)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON reporting."""
        return {
            "subnet": self.subnet,
            "scan_duration_seconds": self.duration_seconds,
            "total_hosts_scanned": len(self.hosts),
            "alive_hosts_count": len(self.alive_hosts),
            "hosts": [h.to_dict() for h in self.hosts if h.is_alive],
        }


class NetworkMapper:
    """
    Network discovery and host mapping tool.

    Scans a given subnet to identify live hosts using ICMP ping and
    optional TCP probes. Performs reverse DNS lookups and TTL-based
    OS fingerprinting on responsive hosts.

    Args:
        subnet: Network address in CIDR notation (e.g., "192.168.1.0/24").
        timeout: Ping/connection timeout in seconds per host.
        max_threads: Maximum concurrent discovery threads.
    """

    def __init__(
        self,
        subnet: str,
        timeout: float = 2.0,
        max_threads: int = 50,
    ) -> None:
        self.timeout = timeout
        self.max_threads = max_threads

        # Validate and parse the subnet
        try:
            self.network = ipaddress.IPv4Network(subnet, strict=False)
            self.subnet = str(self.network)
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise ValueError(
                f"Invalid subnet '{subnet}': {exc}. "
                f"Use CIDR notation like '192.168.1.0/24'."
            ) from exc

    def _ping_host(self, ip: str) -> HostInfo:
        """
        Ping a single host using the system's ping command.

        Parses the output to extract TTL and response time for
        OS fingerprinting.

        Args:
            ip: IPv4 address string to ping.

        Returns:
            HostInfo with alive status, TTL, and timing data.
        """
        host = HostInfo(ip=ip)
        system = platform.system().lower()

        # Build platform-appropriate ping command
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), ip]

        try:
            start = time.monotonic()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 1,
            )
            elapsed = (time.monotonic() - start) * 1000

            if result.returncode == 0:
                host.is_alive = True
                host.response_time_ms = elapsed
                host.discovery_method = "ICMP ping"

                # Extract TTL from ping output
                ttl_match = re.search(
                    r"ttl[=:](\d+)", result.stdout, re.IGNORECASE
                )
                if ttl_match:
                    host.ttl = int(ttl_match.group(1))
                    host.os_hint = self._guess_os_from_ttl(host.ttl)

                # Extract actual round-trip time if available
                time_match = re.search(
                    r"time[=<](\d+\.?\d*)", result.stdout, re.IGNORECASE
                )
                if time_match:
                    host.response_time_ms = float(time_match.group(1))

        except (subprocess.TimeoutExpired, OSError):
            host.is_alive = False

        return host

    def _tcp_probe(self, ip: str, port: int = 80) -> bool:
        """
        Probe a host using a TCP connection attempt as a fallback
        when ICMP is blocked.

        Args:
            ip: IPv4 address string.
            port: Port to attempt connection on.

        Returns:
            True if the host responded (port open or refused).
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            # connect_ex returns 0 for success, but any response
            # (including RST/connection refused) indicates the host is alive.
            # Only timeout indicates the host is down.
            return result == 0 or result == 111  # 111 = connection refused
        except (socket.timeout, OSError):
            return False

    def _resolve_hostname(self, ip: str) -> str:
        """
        Perform reverse DNS lookup on an IP address.

        Args:
            ip: IPv4 address string.

        Returns:
            Hostname string, or empty string if lookup fails.
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""

    def _quick_port_check(self, ip: str) -> list[int]:
        """
        Perform a quick check of a few common ports on a discovered host.

        This provides a preview of running services without performing
        a full port scan.

        Args:
            ip: IPv4 address of a live host.

        Returns:
            List of open port numbers.
        """
        common_ports = [22, 80, 443, 445, 3389, 8080]
        open_ports: list[int] = []

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except (socket.timeout, OSError):
                continue

        return open_ports

    @staticmethod
    def _guess_os_from_ttl(ttl: int) -> str:
        """
        Estimate the operating system based on the observed TTL value.

        TTL decrements by 1 per hop, so we compare against known
        default initial TTL values used by different OS families.

        Args:
            ttl: Time-to-live value from ping response.

        Returns:
            OS guess string based on TTL heuristics.
        """
        for ttl_range, os_name in TTL_FINGERPRINTS.items():
            if ttl in ttl_range:
                return os_name
        return "Unknown"

    def _parse_arp_table(self) -> dict[str, str]:
        """
        Parse the system ARP table to extract IP-to-MAC mappings.

        Uses the 'arp -a' command which is available on most platforms.

        Returns:
            Dictionary mapping IP addresses to MAC addresses.
        """
        arp_map: dict[str, str] = {}

        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            for line in result.stdout.splitlines():
                # Match common arp output formats:
                #   macOS/Linux: host (192.168.1.1) at aa:bb:cc:dd:ee:ff ...
                #   Windows:     192.168.1.1    aa-bb-cc-dd-ee-ff   dynamic
                ip_match = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\)", line
                )
                mac_match = re.search(
                    r"([\da-fA-F]{1,2}[:-]){5}[\da-fA-F]{1,2}", line
                )

                if ip_match and mac_match:
                    ip_addr = ip_match.group(1)
                    mac_addr = mac_match.group(0).lower()
                    # Skip incomplete entries
                    if mac_addr != "ff:ff:ff:ff:ff:ff":
                        arp_map[ip_addr] = mac_addr

        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            pass

        return arp_map

    def _discover_host(self, ip: str, arp_table: dict[str, str]) -> HostInfo:
        """
        Full discovery pipeline for a single host: ping, resolve,
        fingerprint, and check common ports.

        Args:
            ip: IPv4 address string to probe.
            arp_table: Pre-fetched ARP table for MAC lookups.

        Returns:
            Fully populated HostInfo.
        """
        # Step 1: ICMP ping
        host = self._ping_host(ip)

        # Step 2: If ping fails, try TCP probe as fallback
        if not host.is_alive:
            for probe_port in (80, 443, 22):
                if self._tcp_probe(ip, probe_port):
                    host.is_alive = True
                    host.discovery_method = f"TCP probe (port {probe_port})"
                    break

        # Step 3: Enrich data for alive hosts
        if host.is_alive:
            host.hostname = self._resolve_hostname(ip)
            host.mac_address = arp_table.get(ip, "")
            host.open_ports = self._quick_port_check(ip)

            # If we didn't get OS hint from ping TTL, guess from open ports
            if not host.os_hint and host.open_ports:
                if 3389 in host.open_ports or 445 in host.open_ports:
                    host.os_hint = "Likely Windows (RDP/SMB detected)"
                elif 22 in host.open_ports:
                    host.os_hint = "Likely Linux/Unix (SSH detected)"

        return host

    def discover(self) -> NetworkMap:
        """
        Execute full network discovery across the subnet.

        Performs concurrent host probing using a thread pool, enriches
        results with hostname resolution, MAC addresses from ARP table,
        and OS fingerprinting.

        Returns:
            NetworkMap containing all discovered hosts and metadata.
        """
        network_map = NetworkMap(
            subnet=self.subnet,
            scan_start=time.time(),
        )

        # Pre-fetch ARP table for MAC address lookups
        arp_table = self._parse_arp_table()

        # Generate list of host IPs in the subnet (exclude network/broadcast)
        host_ips = [str(ip) for ip in self.network.hosts()]

        # Concurrent host discovery
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {
                executor.submit(self._discover_host, ip, arp_table): ip
                for ip in host_ips
            }

            for future in as_completed(future_to_ip):
                try:
                    host_info = future.result()
                    network_map.hosts.append(host_info)
                except Exception:
                    ip = future_to_ip[future]
                    network_map.hosts.append(HostInfo(ip=ip, is_alive=False))

        # Sort hosts by IP address for clean output
        network_map.hosts.sort(
            key=lambda h: ipaddress.IPv4Address(h.ip)
        )
        network_map.scan_end = time.time()

        return network_map

    @staticmethod
    def get_local_subnet() -> str:
        """
        Auto-detect the local machine's subnet in CIDR notation.

        Connects to a public DNS server (without sending data) to
        determine the local IP, then assumes a /24 subnet.

        Returns:
            Subnet string in CIDR notation (e.g., "192.168.1.0/24").
        """
        try:
            # This doesn't send any data, just determines the local IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()

            # Assume /24 subnet (most common for home/small office)
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            return str(network)

        except OSError:
            return "192.168.1.0/24"
