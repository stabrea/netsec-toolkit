"""Tests for the vulnerability checker module."""

from netsec_toolkit.vuln_checker import (
    DEPRECATED_TLS,
    EXPECTED_SECURITY_HEADERS,
    SENSITIVE_PORTS,
    Finding,
    Severity,
    VulnReport,
    VulnerabilityChecker,
)


def test_severity_enum_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_severity_all_members():
    members = [s for s in Severity]
    assert len(members) == 5


def test_sensitive_ports_has_expected_entries():
    assert 22 not in SENSITIVE_PORTS  # SSH is not in sensitive list
    assert 23 in SENSITIVE_PORTS      # Telnet is sensitive
    assert 445 in SENSITIVE_PORTS     # SMB is sensitive
    assert 3389 in SENSITIVE_PORTS    # RDP is sensitive
    assert 6379 in SENSITIVE_PORTS    # Redis is sensitive
    assert 27017 in SENSITIVE_PORTS   # MongoDB is sensitive


def test_sensitive_ports_structure():
    """Each entry should be a tuple of (service_name, description)."""
    for port, value in SENSITIVE_PORTS.items():
        assert isinstance(port, int)
        assert isinstance(value, tuple)
        assert len(value) == 2
        service_name, description = value
        assert isinstance(service_name, str)
        assert isinstance(description, str)


def test_deprecated_tls_versions():
    assert "SSLv2" in DEPRECATED_TLS
    assert "SSLv3" in DEPRECATED_TLS
    assert "TLSv1" in DEPRECATED_TLS
    assert "TLSv1.0" in DEPRECATED_TLS
    assert "TLSv1.1" in DEPRECATED_TLS
    # Modern versions should NOT be deprecated
    assert "TLSv1.2" not in DEPRECATED_TLS
    assert "TLSv1.3" not in DEPRECATED_TLS


def test_expected_security_headers():
    assert "Strict-Transport-Security" in EXPECTED_SECURITY_HEADERS
    assert "Content-Security-Policy" in EXPECTED_SECURITY_HEADERS
    assert "X-Frame-Options" in EXPECTED_SECURITY_HEADERS
    assert "X-Content-Type-Options" in EXPECTED_SECURITY_HEADERS
    assert len(EXPECTED_SECURITY_HEADERS) >= 5


def test_finding_dataclass():
    finding = Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        description="A test vulnerability.",
        port=443,
        remediation="Fix it.",
        details={"key": "value"},
    )
    assert finding.title == "Test Finding"
    assert finding.severity == Severity.HIGH
    assert finding.description == "A test vulnerability."
    assert finding.port == 443
    assert finding.remediation == "Fix it."
    assert finding.details == {"key": "value"}


def test_finding_to_dict():
    finding = Finding(
        title="Open SMB",
        severity=Severity.HIGH,
        description="SMB exposed",
        port=445,
        remediation="Close port 445",
    )
    d = finding.to_dict()
    assert d["title"] == "Open SMB"
    assert d["severity"] == "high"
    assert d["description"] == "SMB exposed"
    assert d["port"] == 445
    assert d["remediation"] == "Close port 445"


def test_finding_to_dict_omits_empty_optional_fields():
    finding = Finding(
        title="Info",
        severity=Severity.INFO,
        description="Informational",
    )
    d = finding.to_dict()
    assert "port" not in d  # port is 0 -> falsy
    assert "remediation" not in d
    assert "details" not in d


def test_vuln_report_severity_counts():
    report = VulnReport(target="test", scan_start=1000.0, scan_end=1001.0)
    report.findings = [
        Finding(title="A", severity=Severity.CRITICAL, description=""),
        Finding(title="B", severity=Severity.CRITICAL, description=""),
        Finding(title="C", severity=Severity.HIGH, description=""),
        Finding(title="D", severity=Severity.MEDIUM, description=""),
        Finding(title="E", severity=Severity.LOW, description=""),
        Finding(title="F", severity=Severity.INFO, description=""),
        Finding(title="G", severity=Severity.INFO, description=""),
    ]
    assert report.critical_count == 2
    assert report.high_count == 1
    assert report.medium_count == 1
    assert report.low_count == 1
    assert report.info_count == 2


def test_vuln_report_to_dict():
    report = VulnReport(target="example.com", scan_start=1000.0, scan_end=1005.0)
    report.findings = [
        Finding(title="Test", severity=Severity.MEDIUM, description="desc"),
    ]
    d = report.to_dict()
    assert d["target"] == "example.com"
    assert d["scan_duration_seconds"] == 5.0
    assert d["summary"]["total_findings"] == 1
    assert d["summary"]["medium"] == 1
    assert len(d["findings"]) == 1


def test_vuln_report_empty_findings():
    report = VulnReport(target="clean-host", scan_start=100.0, scan_end=101.0)
    assert report.critical_count == 0
    assert report.high_count == 0
    d = report.to_dict()
    assert d["summary"]["total_findings"] == 0


def test_vulnerability_checker_init():
    checker = VulnerabilityChecker("192.168.1.1", timeout=5.0)
    assert checker.target == "192.168.1.1"
    assert checker.timeout == 5.0
