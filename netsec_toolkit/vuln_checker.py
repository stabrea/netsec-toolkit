"""
Vulnerability Checker Module

Performs basic security checks against a target host to identify common
misconfigurations and potential vulnerabilities. Checks include:

- Open service detection on sensitive ports
- SSH configuration analysis
- SSL/TLS version and cipher strength checks
- Default credential port exposure
- HTTP security header analysis
- DNS zone transfer attempts

This is not a replacement for professional vulnerability scanners (Nessus,
OpenVAS, etc.) but provides quick security posture assessment.

Usage:
    checker = VulnerabilityChecker("192.168.1.1")
    findings = checker.run_all_checks()
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class Severity(Enum):
    """Vulnerability severity levels following CVSS-style categorization."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single vulnerability or security finding."""
    title: str
    severity: Severity
    description: str
    port: int = 0
    remediation: str = ""
    details: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON reporting."""
        result: dict = {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
        }
        if self.port:
            result["port"] = self.port
        if self.remediation:
            result["remediation"] = self.remediation
        if self.details:
            result["details"] = self.details
        return result


@dataclass
class VulnReport:
    """Aggregated vulnerability assessment report."""
    target: str
    scan_start: float
    scan_end: float = 0.0
    findings: list[Finding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def duration_seconds(self) -> float:
        return round(self.scan_end - self.scan_start, 2)

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON reporting."""
        return {
            "target": self.target,
            "scan_duration_seconds": self.duration_seconds,
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# Ports that are commonly associated with security risks when exposed
SENSITIVE_PORTS: dict[int, tuple[str, str]] = {
    21: ("FTP", "FTP allows unencrypted file transfers and is often misconfigured"),
    23: ("Telnet", "Telnet transmits all data including credentials in plaintext"),
    25: ("SMTP", "Open SMTP relay can be abused for spam"),
    135: ("MS-RPC", "MS-RPC is frequently targeted by worms and exploits"),
    139: ("NetBIOS", "NetBIOS exposes system information and file shares"),
    445: ("SMB", "SMB is a primary target for ransomware (EternalBlue, WannaCry)"),
    1433: ("MSSQL", "Database server should not be directly exposed"),
    1521: ("Oracle DB", "Database server should not be directly exposed"),
    3306: ("MySQL", "Database server should not be directly exposed"),
    3389: ("RDP", "RDP is a frequent target for brute force and BlueKeep-style exploits"),
    5432: ("PostgreSQL", "Database server should not be directly exposed"),
    5900: ("VNC", "VNC often has weak authentication"),
    6379: ("Redis", "Redis often runs without authentication by default"),
    9200: ("Elasticsearch", "Elasticsearch often has no authentication"),
    11211: ("Memcached", "Memcached can be abused for DDoS amplification"),
    27017: ("MongoDB", "MongoDB historically defaults to no authentication"),
}

# SSL/TLS versions and their security status
DEPRECATED_TLS: set[str] = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

# HTTP security headers that should be present
EXPECTED_SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "Enables HSTS to prevent protocol downgrade attacks",
    "X-Content-Type-Options": "Prevents MIME type sniffing attacks",
    "X-Frame-Options": "Prevents clickjacking attacks via iframe embedding",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks",
    "X-XSS-Protection": "Enables browser XSS filtering (legacy but still useful)",
    "Referrer-Policy": "Controls information leakage in the Referer header",
    "Permissions-Policy": "Restricts browser features available to the page",
}


class VulnerabilityChecker:
    """
    Security vulnerability and misconfiguration checker.

    Runs a suite of checks against a target host to identify common
    security issues. Each check is independent and results are
    aggregated into a VulnReport.

    Args:
        target: Hostname or IP address to assess.
        timeout: Connection timeout in seconds for each check.
    """

    def __init__(self, target: str, timeout: float = 3.0) -> None:
        self.target = target
        self.timeout = timeout
        self._resolved_ip: str = ""

    def _resolve(self) -> None:
        """Resolve and cache the target IP address."""
        if not self._resolved_ip:
            try:
                self._resolved_ip = socket.gethostbyname(self.target)
            except socket.gaierror as exc:
                raise ConnectionError(
                    f"Cannot resolve '{self.target}': {exc}"
                ) from exc

    def _check_port_open(self, port: int) -> bool:
        """Quick TCP connect check to determine if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self._resolved_ip, port))
            sock.close()
            return result == 0
        except (socket.timeout, OSError):
            return False

    def check_sensitive_ports(self) -> list[Finding]:
        """
        Check for sensitive services exposed on well-known ports.

        Tests each port in SENSITIVE_PORTS and creates findings for
        any that are open and reachable.

        Returns:
            List of findings for exposed sensitive services.
        """
        findings: list[Finding] = []

        for port, (service, description) in SENSITIVE_PORTS.items():
            if self._check_port_open(port):
                # Determine severity based on service type
                match service:
                    case "Telnet" | "SMB" | "Redis" | "MongoDB":
                        severity = Severity.HIGH
                    case "RDP" | "VNC" | "FTP":
                        severity = Severity.HIGH
                    case "MSSQL" | "MySQL" | "PostgreSQL" | "Oracle DB":
                        severity = Severity.MEDIUM
                    case _:
                        severity = Severity.MEDIUM

                findings.append(Finding(
                    title=f"Exposed {service} Service",
                    severity=severity,
                    description=description,
                    port=port,
                    remediation=(
                        f"If {service} is not required, close port {port}. "
                        f"If required, restrict access via firewall rules "
                        f"and ensure strong authentication is configured."
                    ),
                ))

        return findings

    def check_ssh_configuration(self) -> list[Finding]:
        """
        Analyze SSH server configuration by connecting and examining
        the banner and supported features.

        Checks for:
        - SSH version (v1 is insecure)
        - Banner information disclosure
        - Protocol version

        Returns:
            List of findings related to SSH configuration.
        """
        findings: list[Finding] = []

        if not self._check_port_open(22):
            return findings

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self._resolved_ip, 22))

            # SSH servers send a banner on connect
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()

            if banner:
                # Check for SSH protocol version 1 (deprecated)
                if "SSH-1" in banner and "SSH-2" not in banner:
                    findings.append(Finding(
                        title="SSH Protocol Version 1 Detected",
                        severity=Severity.CRITICAL,
                        description=(
                            "SSH v1 has known cryptographic weaknesses "
                            "and is vulnerable to session hijacking."
                        ),
                        port=22,
                        remediation="Upgrade to SSH v2 and disable v1 in sshd_config.",
                        details={"banner": banner},
                    ))
                elif "SSH-2" in banner or "SSH-1.99" in banner:
                    findings.append(Finding(
                        title="SSH Service Detected",
                        severity=Severity.INFO,
                        description="SSH v2 is running (secure protocol version).",
                        port=22,
                        details={"banner": banner},
                    ))

                # Check for software version disclosure
                # Banner usually contains: SSH-2.0-OpenSSH_8.9p1
                if "OpenSSH" in banner or "dropbear" in banner:
                    findings.append(Finding(
                        title="SSH Software Version Disclosure",
                        severity=Severity.LOW,
                        description=(
                            "The SSH server discloses its software version. "
                            "Attackers can use this to find version-specific "
                            "vulnerabilities."
                        ),
                        port=22,
                        remediation=(
                            "Consider customizing the SSH banner to remove "
                            "version information (limited options in OpenSSH)."
                        ),
                        details={"banner": banner},
                    ))

        except (socket.timeout, OSError):
            pass

        return findings

    def check_ssl_tls(self, port: int = 443) -> list[Finding]:
        """
        Assess SSL/TLS configuration on a given port.

        Checks for:
        - Deprecated protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
        - Weak cipher suites
        - Certificate validity and key strength
        - Self-signed certificates

        Args:
            port: Port to check for SSL/TLS (default: 443).

        Returns:
            List of SSL/TLS related findings.
        """
        findings: list[Finding] = []

        if not self._check_port_open(port):
            return findings

        # Check current negotiated protocol
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (self._resolved_ip, port), timeout=self.timeout
            ) as raw_sock:
                with context.wrap_socket(
                    raw_sock, server_hostname=self.target
                ) as ssl_sock:
                    protocol = ssl_sock.version() or ""
                    cipher = ssl_sock.cipher()

                    # Check for deprecated protocols
                    if protocol in DEPRECATED_TLS:
                        findings.append(Finding(
                            title=f"Deprecated TLS Version: {protocol}",
                            severity=Severity.HIGH,
                            description=(
                                f"The server negotiated {protocol}, which has "
                                f"known vulnerabilities (POODLE, BEAST, etc.)."
                            ),
                            port=port,
                            remediation=(
                                "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. "
                                "Enable only TLS 1.2 and TLS 1.3."
                            ),
                            details={"protocol": protocol},
                        ))
                    else:
                        findings.append(Finding(
                            title=f"TLS Version: {protocol}",
                            severity=Severity.INFO,
                            description=f"Server supports {protocol}.",
                            port=port,
                            details={"protocol": protocol},
                        ))

                    # Check cipher strength
                    if cipher:
                        cipher_name, _, cipher_bits = cipher
                        if cipher_bits < 128:
                            findings.append(Finding(
                                title="Weak Cipher Suite Detected",
                                severity=Severity.HIGH,
                                description=(
                                    f"Cipher {cipher_name} uses only "
                                    f"{cipher_bits}-bit encryption."
                                ),
                                port=port,
                                remediation=(
                                    "Configure the server to prefer 128-bit "
                                    "or stronger cipher suites."
                                ),
                                details={
                                    "cipher": cipher_name,
                                    "bits": str(cipher_bits),
                                },
                            ))
                        elif "RC4" in cipher_name or "DES" in cipher_name:
                            findings.append(Finding(
                                title="Insecure Cipher Algorithm",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"Cipher {cipher_name} uses a known-weak "
                                    f"algorithm (RC4 or DES)."
                                ),
                                port=port,
                                remediation="Disable RC4 and DES cipher suites.",
                                details={"cipher": cipher_name},
                            ))

        except ssl.SSLError as exc:
            findings.append(Finding(
                title="SSL/TLS Connection Error",
                severity=Severity.MEDIUM,
                description=f"SSL handshake failed: {exc}",
                port=port,
                remediation="Verify SSL/TLS configuration on the server.",
            ))
        except (socket.timeout, OSError):
            pass

        # Try to verify the certificate properly
        try:
            verify_ctx = ssl.create_default_context()
            with socket.create_connection(
                (self._resolved_ip, port), timeout=self.timeout
            ) as raw_sock:
                with verify_ctx.wrap_socket(
                    raw_sock, server_hostname=self.target
                ) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    if cert:
                        findings.append(Finding(
                            title="Valid SSL Certificate",
                            severity=Severity.INFO,
                            description="Certificate is trusted by the system CA store.",
                            port=port,
                        ))
        except ssl.SSLCertVerificationError:
            findings.append(Finding(
                title="Untrusted SSL Certificate",
                severity=Severity.MEDIUM,
                description=(
                    "The certificate is not trusted. It may be self-signed, "
                    "expired, or issued by an unknown CA."
                ),
                port=port,
                remediation=(
                    "Obtain a certificate from a trusted CA (e.g., Let's Encrypt) "
                    "and ensure the certificate chain is complete."
                ),
            ))
        except (socket.timeout, OSError, ssl.SSLError):
            pass

        return findings

    def check_http_security_headers(self, port: int = 80) -> list[Finding]:
        """
        Check for the presence of security-related HTTP headers.

        Connects to the HTTP service and examines response headers for
        missing security controls.

        Args:
            port: HTTP port to check (default: 80).

        Returns:
            List of findings for missing security headers.
        """
        findings: list[Finding] = []

        if not self._check_port_open(port):
            return findings

        try:
            # Use http.client for direct header inspection
            if port == 443:
                conn = http.client.HTTPSConnection(
                    self._resolved_ip,
                    port=port,
                    timeout=self.timeout,
                    context=ssl._create_unverified_context(),
                )
            else:
                conn = http.client.HTTPConnection(
                    self._resolved_ip,
                    port=port,
                    timeout=self.timeout,
                )

            conn.request("HEAD", "/", headers={"Host": self.target})
            response = conn.getresponse()
            headers = {k.lower(): v for k, v in response.getheaders()}
            conn.close()

            # Check server header (information disclosure)
            server_header = headers.get("server", "")
            if server_header:
                findings.append(Finding(
                    title="Server Header Information Disclosure",
                    severity=Severity.LOW,
                    description=(
                        f"The server header reveals: '{server_header}'. "
                        f"This aids attackers in identifying the web server "
                        f"software and version."
                    ),
                    port=port,
                    remediation="Remove or obscure the Server header.",
                    details={"server_header": server_header},
                ))

            # Check for missing security headers
            for header, purpose in EXPECTED_SECURITY_HEADERS.items():
                if header.lower() not in headers:
                    findings.append(Finding(
                        title=f"Missing Security Header: {header}",
                        severity=Severity.MEDIUM,
                        description=f"The {header} header is not set. {purpose}.",
                        port=port,
                        remediation=f"Add the {header} header to HTTP responses.",
                    ))

            # Check for cookies without security flags
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                cookie_lower = set_cookie.lower()
                if "secure" not in cookie_lower:
                    findings.append(Finding(
                        title="Cookie Missing Secure Flag",
                        severity=Severity.MEDIUM,
                        description="Cookies are set without the Secure flag.",
                        port=port,
                        remediation="Set the Secure flag on all cookies.",
                    ))
                if "httponly" not in cookie_lower:
                    findings.append(Finding(
                        title="Cookie Missing HttpOnly Flag",
                        severity=Severity.MEDIUM,
                        description=(
                            "Cookies are set without the HttpOnly flag, "
                            "making them accessible to JavaScript (XSS risk)."
                        ),
                        port=port,
                        remediation="Set the HttpOnly flag on session cookies.",
                    ))

        except (http.client.HTTPException, OSError, socket.timeout):
            pass

        return findings

    def check_dns_zone_transfer(self) -> list[Finding]:
        """
        Attempt a DNS zone transfer (AXFR) against the target.

        Zone transfers expose the entire DNS zone, revealing all
        hostnames, IP addresses, and internal network structure.

        Returns:
            List of findings if zone transfer is allowed.
        """
        findings: list[Finding] = []

        if not self._check_port_open(53):
            return findings

        # Build a minimal AXFR request manually using raw sockets.
        # DNS AXFR query structure:
        #   Transaction ID (2 bytes)
        #   Flags (2 bytes) - standard query
        #   Questions (2 bytes) - 1
        #   Answer/Auth/Additional RRs (6 bytes) - 0 each
        #   Query name (variable) - domain name
        #   Query type (2 bytes) - AXFR (252)
        #   Query class (2 bytes) - IN (1)

        try:
            # Encode the domain name in DNS wire format
            domain_parts = self.target.split(".")
            qname = b""
            for part in domain_parts:
                qname += bytes([len(part)]) + part.encode()
            qname += b"\x00"  # Root label

            # Build the DNS query
            import struct
            query = struct.pack(
                ">HHHHHH",
                0x1337,  # Transaction ID
                0x0000,  # Flags: standard query
                1,       # Questions
                0, 0, 0  # Answer, Authority, Additional RRs
            )
            query += qname
            query += struct.pack(">HH", 252, 1)  # AXFR, IN class

            # Send over TCP (zone transfers use TCP)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self._resolved_ip, 53))

            # TCP DNS messages are prefixed with 2-byte length
            tcp_msg = struct.pack(">H", len(query)) + query
            sock.sendall(tcp_msg)

            # Read response length
            response_len_data = sock.recv(2)
            if len(response_len_data) == 2:
                response_len = struct.unpack(">H", response_len_data)[0]
                response = sock.recv(response_len)

                # Check response flags for success
                if len(response) >= 4:
                    flags = struct.unpack(">H", response[2:4])[0]
                    rcode = flags & 0x000F
                    answer_count = struct.unpack(">H", response[6:8])[0]

                    if rcode == 0 and answer_count > 0:
                        findings.append(Finding(
                            title="DNS Zone Transfer Allowed",
                            severity=Severity.HIGH,
                            description=(
                                "The DNS server allows zone transfers (AXFR). "
                                "This exposes the complete DNS zone data "
                                "including all hostnames and IP addresses."
                            ),
                            port=53,
                            remediation=(
                                "Restrict zone transfers to authorized "
                                "secondary DNS servers only using ACLs."
                            ),
                            details={
                                "records_in_response": str(answer_count),
                            },
                        ))

            sock.close()

        except (socket.timeout, OSError, struct.error):
            pass

        return findings

    def run_all_checks(self) -> VulnReport:
        """
        Execute all vulnerability checks against the target.

        Runs each check module sequentially and aggregates all
        findings into a comprehensive report sorted by severity.

        Returns:
            VulnReport containing all findings and metadata.
        """
        self._resolve()

        report = VulnReport(
            target=self.target,
            scan_start=time.time(),
        )

        # Define all check functions to run
        checks: list[Callable[[], list[Finding]]] = [
            self.check_sensitive_ports,
            self.check_ssh_configuration,
            self.check_ssl_tls,
            lambda: self.check_http_security_headers(80),
            lambda: self.check_http_security_headers(443),
            self.check_dns_zone_transfer,
        ]

        for check in checks:
            try:
                findings = check()
                report.findings.extend(findings)
            except Exception:
                # Individual check failures should not abort the assessment
                continue

        # Sort findings by severity (critical first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        report.findings.sort(key=lambda f: severity_order[f.severity])
        report.scan_end = time.time()

        return report
