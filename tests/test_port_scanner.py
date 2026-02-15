"""Tests for the port scanner module."""

from netsec_toolkit.port_scanner import (
    COMMON_SERVICES,
    TOP_20_PORTS,
    TOP_100_PORTS,
    ALL_PORTS_RANGE,
    PortResult,
    PortState,
    PortScanner,
    ScanResult,
)


def test_port_scanner_init_defaults():
    scanner = PortScanner("127.0.0.1")
    assert scanner.target == "127.0.0.1"
    assert scanner.timeout == 2.0
    assert scanner.max_threads == 100
    assert scanner.grab_banners is True


def test_port_scanner_init_custom():
    scanner = PortScanner("example.com", timeout=5.0, max_threads=50, grab_banners=False)
    assert scanner.target == "example.com"
    assert scanner.timeout == 5.0
    assert scanner.max_threads == 50
    assert scanner.grab_banners is False


def test_common_services_has_expected_entries():
    assert 22 in COMMON_SERVICES
    assert COMMON_SERVICES[22] == "SSH"
    assert 80 in COMMON_SERVICES
    assert COMMON_SERVICES[80] == "HTTP"
    assert 443 in COMMON_SERVICES
    assert COMMON_SERVICES[443] == "HTTPS"
    assert 3306 in COMMON_SERVICES
    assert COMMON_SERVICES[3306] == "MySQL"


def test_common_services_is_nonempty():
    assert len(COMMON_SERVICES) > 10


def test_top_20_ports_length():
    assert len(TOP_20_PORTS) == 20


def test_top_100_ports_contains_top_20():
    for port in TOP_20_PORTS:
        assert port in TOP_100_PORTS


def test_all_ports_range():
    assert ALL_PORTS_RANGE.start == 1
    assert ALL_PORTS_RANGE.stop == 65536


def test_port_result_dataclass_defaults():
    result = PortResult(port=80, state=PortState.OPEN)
    assert result.port == 80
    assert result.state == PortState.OPEN
    assert result.service == ""
    assert result.banner == ""
    assert result.response_time_ms == 0.0
    assert result.ssl_info == {}


def test_port_result_to_dict():
    result = PortResult(
        port=443,
        state=PortState.OPEN,
        service="HTTPS",
        banner="nginx",
        response_time_ms=12.5,
        ssl_info={"protocol": "TLSv1.3"},
    )
    d = result.to_dict()
    assert d["port"] == 443
    assert d["state"] == "open"
    assert d["service"] == "HTTPS"
    assert d["banner"] == "nginx"
    assert d["response_time_ms"] == 12.5
    assert d["ssl_info"]["protocol"] == "TLSv1.3"


def test_port_result_to_dict_omits_empty_banner_and_ssl():
    result = PortResult(port=22, state=PortState.CLOSED, service="SSH")
    d = result.to_dict()
    assert "banner" not in d
    assert "ssl_info" not in d


def test_port_state_enum_values():
    assert PortState.OPEN.value == "open"
    assert PortState.CLOSED.value == "closed"
    assert PortState.FILTERED.value == "filtered"


def test_scan_result_open_ports_property():
    scan = ScanResult(target="test", resolved_ip="1.2.3.4", scan_start=1000.0)
    scan.ports = [
        PortResult(port=22, state=PortState.OPEN),
        PortResult(port=23, state=PortState.CLOSED),
        PortResult(port=80, state=PortState.OPEN),
        PortResult(port=443, state=PortState.FILTERED),
    ]
    open_ports = scan.open_ports
    assert len(open_ports) == 2
    assert all(p.state == PortState.OPEN for p in open_ports)


def test_scan_result_duration():
    scan = ScanResult(target="test", resolved_ip="1.2.3.4", scan_start=1000.0, scan_end=1002.5)
    assert scan.duration_seconds == 2.5


def test_scan_result_to_dict():
    scan = ScanResult(target="test", resolved_ip="1.2.3.4", scan_start=1000.0, scan_end=1001.0)
    scan.ports = [PortResult(port=80, state=PortState.OPEN, service="HTTP")]
    d = scan.to_dict()
    assert d["target"] == "test"
    assert d["resolved_ip"] == "1.2.3.4"
    assert d["total_ports_scanned"] == 1
    assert d["open_ports_count"] == 1
    assert len(d["ports"]) == 1
