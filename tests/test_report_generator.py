"""Tests for the report generator module."""

import json
import os
import tempfile

from netsec_toolkit.port_scanner import PortResult, PortState, ScanResult
from netsec_toolkit.network_mapper import HostInfo, NetworkMap
from netsec_toolkit.vuln_checker import Finding, Severity, VulnReport
from netsec_toolkit.report_generator import ReportGenerator, ReportData, _escape_html


def _make_scan_result() -> ScanResult:
    scan = ScanResult(target="test-host", resolved_ip="10.0.0.1", scan_start=1000.0, scan_end=1002.0)
    scan.ports = [
        PortResult(port=22, state=PortState.OPEN, service="SSH", response_time_ms=5.0),
        PortResult(port=80, state=PortState.OPEN, service="HTTP", response_time_ms=3.0),
        PortResult(port=443, state=PortState.CLOSED, service="HTTPS"),
    ]
    return scan


def _make_vuln_report() -> VulnReport:
    report = VulnReport(target="test-host", scan_start=1000.0, scan_end=1003.0)
    report.findings = [
        Finding(title="Open Telnet", severity=Severity.HIGH, description="Telnet is exposed", port=23),
        Finding(title="Missing HSTS", severity=Severity.MEDIUM, description="No HSTS header", port=80),
    ]
    return report


def test_report_generator_init():
    gen = ReportGenerator(title="My Report", author="Tester")
    assert gen.title == "My Report"
    assert gen.author == "Tester"
    assert isinstance(gen.data, ReportData)


def test_add_port_scan():
    gen = ReportGenerator()
    scan = _make_scan_result()
    gen.add_port_scan(scan)
    assert len(gen.data.port_scans) == 1
    assert gen.data.port_scans[0].target == "test-host"


def test_add_vuln_report():
    gen = ReportGenerator()
    vuln = _make_vuln_report()
    gen.add_vuln_report(vuln)
    assert len(gen.data.vuln_reports) == 1


def test_add_network_map():
    gen = ReportGenerator()
    nm = NetworkMap(subnet="10.0.0.0/24", scan_start=1000.0, scan_end=1005.0)
    nm.hosts = [HostInfo(ip="10.0.0.1", is_alive=True)]
    gen.add_network_map(nm)
    assert len(gen.data.network_maps) == 1


def test_generate_json_creates_valid_file():
    gen = ReportGenerator(title="Test JSON Report", author="CI")
    gen.add_port_scan(_make_scan_result())
    gen.add_vuln_report(_make_vuln_report())

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "report.json")
        result_path = gen.generate_json(out_path)

        assert os.path.isfile(result_path)

        with open(result_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "report_metadata" in data
        assert data["report_metadata"]["title"] == "Test JSON Report"
        assert data["report_metadata"]["author"] == "CI"
        assert "port_scans" in data
        assert len(data["port_scans"]) == 1
        assert "vulnerability_assessments" in data
        assert len(data["vulnerability_assessments"]) == 1


def test_generate_json_port_scan_data():
    gen = ReportGenerator()
    gen.add_port_scan(_make_scan_result())

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "report.json")
        gen.generate_json(out_path)

        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        scan = data["port_scans"][0]
        assert scan["target"] == "test-host"
        assert scan["open_ports_count"] == 2
        assert scan["total_ports_scanned"] == 3


def test_generate_html_creates_file():
    gen = ReportGenerator(title="Test HTML Report")
    gen.add_port_scan(_make_scan_result())
    gen.add_vuln_report(_make_vuln_report())

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "report.html")
        result_path = gen.generate_html(out_path)

        assert os.path.isfile(result_path)

        with open(result_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert "<!DOCTYPE html>" in html
        assert "Test HTML Report" in html
        assert "netsec-toolkit" in html


def test_generate_html_contains_scan_data():
    gen = ReportGenerator()
    gen.add_port_scan(_make_scan_result())

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "report.html")
        gen.generate_html(out_path)

        with open(out_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert "Port Scan Results" in html
        assert "test-host" in html


def test_generate_html_contains_vuln_data():
    gen = ReportGenerator()
    gen.add_vuln_report(_make_vuln_report())

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "report.html")
        gen.generate_html(out_path)

        with open(out_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert "Vulnerability Findings" in html
        assert "Open Telnet" in html
        assert "Missing HSTS" in html


def test_escape_html():
    assert _escape_html('<script>alert("xss")</script>') == '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
    assert _escape_html("safe text") == "safe text"
    assert _escape_html("a & b") == "a &amp; b"
    assert _escape_html("it's") == "it&#x27;s"


def test_generate_json_empty_report():
    gen = ReportGenerator()
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "empty.json")
        gen.generate_json(out_path)

        with open(out_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "report_metadata" in data
        assert "port_scans" not in data
        assert "vulnerability_assessments" not in data
