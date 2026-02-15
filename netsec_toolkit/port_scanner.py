"""
TCP Port Scanner Module

Performs TCP connect scans against target hosts to identify open ports,
detect running services, and grab banners for service fingerprinting.

This module uses raw socket connections (TCP connect scan) rather than
SYN scans, so it does not require root privileges but is detectable
by intrusion detection systems.

Usage:
    scanner = PortScanner("192.168.1.1", timeout=1.5)
    results = scanner.scan(ports=[22, 80, 443, 8080])
"""

from __future__ import annotations

import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence


class PortState(Enum):
    """Enumeration of possible port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


# Well-known port-to-service mappings for common services.
# This avoids relying on /etc/services and keeps the tool portable.
COMMON_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Predefined port lists for different scan profiles.
TOP_20_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443,
]

TOP_100_PORTS: list[int] = sorted(set(
    TOP_20_PORTS + [
        20, 26, 37, 49, 69, 79, 81, 88, 106, 113,
        119, 123, 137, 138, 161, 162, 179, 194, 389, 427,
        443, 464, 465, 497, 500, 512, 513, 514, 515, 520,
        523, 540, 548, 554, 587, 593, 625, 631, 636, 646,
        666, 749, 873, 902, 990, 992, 993, 995, 1025, 1080,
        1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2181,
        2222, 3000, 3128, 3268, 3389, 3690, 4000, 4444, 4443, 4993,
        5000, 5001, 5060, 5222, 5432, 5500, 5632, 5900, 5984, 6000,
        6379, 6667, 7001, 7199, 8000, 8008, 8080, 8081, 8443, 8888,
        9000, 9090, 9200, 9300, 9418, 9999, 10000, 11211, 27017, 50000,
    ]
))

ALL_PORTS_RANGE: range = range(1, 65536)


@dataclass
class PortResult:
    """Result of scanning a single port."""
    port: int
    state: PortState
    service: str = ""
    banner: str = ""
    response_time_ms: float = 0.0
    ssl_info: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON reporting."""
        result: dict = {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "response_time_ms": round(self.response_time_ms, 2),
        }
        if self.banner:
            result["banner"] = self.banner
        if self.ssl_info:
            result["ssl_info"] = self.ssl_info
        return result


@dataclass
class ScanResult:
    """Aggregated results from a full port scan."""
    target: str
    resolved_ip: str
    scan_start: float
    scan_end: float = 0.0
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        """Return only ports that are open."""
        return [p for p in self.ports if p.state == PortState.OPEN]

    @property
    def duration_seconds(self) -> float:
        """Total scan duration in seconds."""
        return round(self.scan_end - self.scan_start, 2)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON reporting."""
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "scan_duration_seconds": self.duration_seconds,
            "total_ports_scanned": len(self.ports),
            "open_ports_count": len(self.open_ports),
            "ports": [p.to_dict() for p in self.ports],
        }


class PortScanner:
    """
    TCP connect port scanner with service detection and banner grabbing.

    Performs full TCP handshake to determine port state. Supports concurrent
    scanning via thread pool and optional SSL/TLS probing for encrypted
    services.

    Args:
        target: Hostname or IP address to scan.
        timeout: Connection timeout in seconds per port.
        max_threads: Maximum concurrent scanning threads.
        grab_banners: Whether to attempt banner grabbing on open ports.
    """

    def __init__(
        self,
        target: str,
        timeout: float = 2.0,
        max_threads: int = 100,
        grab_banners: bool = True,
    ) -> None:
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.grab_banners = grab_banners
        self._resolved_ip: str = ""

    def resolve_target(self) -> str:
        """Resolve hostname to IP address. Returns the IP as a string."""
        try:
            self._resolved_ip = socket.gethostbyname(self.target)
            return self._resolved_ip
        except socket.gaierror as exc:
            raise ConnectionError(
                f"Cannot resolve hostname '{self.target}': {exc}"
            ) from exc

    def scan_port(self, port: int) -> PortResult:
        """
        Scan a single TCP port using a connect scan.

        Attempts a full TCP handshake. If successful, optionally grabs
        the service banner and probes for SSL/TLS information on known
        encrypted ports.

        Args:
            port: Port number to scan (1-65535).

        Returns:
            PortResult with state, service name, and optional banner.
        """
        result = PortResult(
            port=port,
            state=PortState.CLOSED,
            service=COMMON_SERVICES.get(port, "unknown"),
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        start_time = time.monotonic()

        try:
            connection_result = sock.connect_ex((self._resolved_ip, port))
            elapsed = (time.monotonic() - start_time) * 1000
            result.response_time_ms = elapsed

            if connection_result == 0:
                result.state = PortState.OPEN

                if self.grab_banners:
                    result.banner = self._grab_banner(sock, port)

                # Probe SSL/TLS on commonly encrypted ports
                if port in (443, 465, 636, 993, 995, 8443, 4443):
                    result.ssl_info = self._probe_ssl(port)

            else:
                result.state = PortState.CLOSED

        except socket.timeout:
            result.state = PortState.FILTERED
            result.response_time_ms = self.timeout * 1000

        except OSError:
            result.state = PortState.FILTERED

        finally:
            sock.close()

        return result

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Attempt to grab the service banner from an open port.

        Some services (like HTTP) require a probe to be sent first.
        Others (like SSH, FTP, SMTP) send a banner on connect.

        Args:
            sock: Connected socket to the target port.
            port: The port number (used to determine probe type).

        Returns:
            Banner string, or empty string if no banner received.
        """
        try:
            # HTTP-like services need a request to elicit a response
            if port in (80, 8080, 8000, 8008, 8888, 8081):
                probe = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {self.target}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(probe.encode())

            # SMTP, FTP, SSH etc. typically send banners unprompted,
            # so we just wait for data
            sock.settimeout(2.0)
            banner_bytes = sock.recv(1024)
            banner = banner_bytes.decode("utf-8", errors="replace").strip()

            # Truncate excessively long banners
            if len(banner) > 500:
                banner = banner[:500] + "..."

            return banner

        except (socket.timeout, OSError, UnicodeDecodeError):
            return ""

    def _probe_ssl(self, port: int) -> dict[str, str]:
        """
        Probe an SSL/TLS-enabled port for certificate and protocol info.

        Creates a new connection with SSL wrapping to extract certificate
        details and the negotiated TLS version.

        Args:
            port: Port number to probe with SSL.

        Returns:
            Dictionary with SSL/TLS details (version, cipher, cert subject).
        """
        ssl_info: dict[str, str] = {}

        try:
            context = ssl.create_default_context()
            # Allow self-signed certs for scanning purposes
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (self._resolved_ip, port), timeout=self.timeout
            ) as raw_sock:
                with context.wrap_socket(
                    raw_sock, server_hostname=self.target
                ) as ssl_sock:
                    ssl_info["protocol"] = ssl_sock.version() or "unknown"
                    cipher = ssl_sock.cipher()
                    if cipher:
                        ssl_info["cipher_suite"] = cipher[0]
                        ssl_info["cipher_bits"] = str(cipher[2])

                    cert = ssl_sock.getpeercert(binary_form=False)
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", ()))
                        ssl_info["cert_subject"] = subject.get(
                            "commonName", "N/A"
                        )
                        ssl_info["cert_issuer"] = str(
                            cert.get("issuer", "N/A")
                        )
                        ssl_info["cert_expires"] = cert.get(
                            "notAfter", "N/A"
                        )

                    # Also grab the binary cert to check key size
                    der_cert = ssl_sock.getpeercert(binary_form=True)
                    if der_cert:
                        ssl_info["cert_size_bytes"] = str(len(der_cert))

        except (ssl.SSLError, OSError, socket.timeout):
            ssl_info["error"] = "SSL probe failed or not SSL-enabled"

        return ssl_info

    def scan(
        self,
        ports: Sequence[int] | None = None,
        profile: str = "top20",
    ) -> ScanResult:
        """
        Execute a full port scan against the target.

        Resolves the target, then scans the specified ports concurrently
        using a thread pool. Results are sorted by port number.

        Args:
            ports: Explicit list of ports to scan. Overrides profile.
            profile: Scan profile if ports not specified.
                     One of: "top20", "top100", "all".

        Returns:
            ScanResult containing all port results and metadata.
        """
        self.resolve_target()

        # Determine which ports to scan
        if ports is not None:
            target_ports = list(ports)
        else:
            match profile:
                case "top20":
                    target_ports = TOP_20_PORTS
                case "top100":
                    target_ports = TOP_100_PORTS
                case "all":
                    target_ports = list(ALL_PORTS_RANGE)
                case _:
                    target_ports = TOP_20_PORTS

        scan_result = ScanResult(
            target=self.target,
            resolved_ip=self._resolved_ip,
            scan_start=time.time(),
        )

        # Use thread pool for concurrent port scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port
                for port in target_ports
            }

            for future in as_completed(future_to_port):
                try:
                    port_result = future.result()
                    scan_result.ports.append(port_result)
                except Exception:
                    port = future_to_port[future]
                    scan_result.ports.append(
                        PortResult(port=port, state=PortState.FILTERED)
                    )

        # Sort results by port number for clean output
        scan_result.ports.sort(key=lambda p: p.port)
        scan_result.scan_end = time.time()

        return scan_result
