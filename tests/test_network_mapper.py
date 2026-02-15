"""Tests for the network mapper module."""

import ipaddress

import pytest

from netsec_toolkit.network_mapper import (
    HostInfo,
    NetworkMap,
    NetworkMapper,
    TTL_FINGERPRINTS,
)


def test_network_mapper_valid_subnet():
    mapper = NetworkMapper("192.168.1.0/24")
    assert mapper.subnet == "192.168.1.0/24"
    assert mapper.network == ipaddress.IPv4Network("192.168.1.0/24")


def test_network_mapper_strict_false():
    # A host address with /24 should still work because strict=False
    mapper = NetworkMapper("192.168.1.50/24")
    assert mapper.subnet == "192.168.1.0/24"


def test_network_mapper_invalid_subnet_raises():
    with pytest.raises(ValueError, match="Invalid subnet"):
        NetworkMapper("not-a-valid-subnet")


def test_network_mapper_empty_string_raises():
    with pytest.raises(ValueError):
        NetworkMapper("")


def test_network_mapper_default_timeout_and_threads():
    mapper = NetworkMapper("10.0.0.0/24")
    assert mapper.timeout == 2.0
    assert mapper.max_threads == 50


def test_network_mapper_custom_timeout_and_threads():
    mapper = NetworkMapper("10.0.0.0/24", timeout=5.0, max_threads=10)
    assert mapper.timeout == 5.0
    assert mapper.max_threads == 10


def test_host_info_defaults():
    host = HostInfo(ip="192.168.1.1")
    assert host.ip == "192.168.1.1"
    assert host.hostname == ""
    assert host.is_alive is False
    assert host.ttl == 0
    assert host.os_hint == ""
    assert host.mac_address == ""
    assert host.response_time_ms == 0.0
    assert host.open_ports == []
    assert host.discovery_method == ""


def test_host_info_to_dict_alive():
    host = HostInfo(
        ip="192.168.1.1",
        hostname="gateway.local",
        is_alive=True,
        ttl=64,
        os_hint="Likely Linux / Unix / Android",
        mac_address="aa:bb:cc:dd:ee:ff",
        response_time_ms=1.5,
        open_ports=[22, 80],
        discovery_method="ICMP ping",
    )
    d = host.to_dict()
    assert d["ip"] == "192.168.1.1"
    assert d["is_alive"] is True
    assert d["hostname"] == "gateway.local"
    assert d["ttl"] == 64
    assert d["os_hint"] == "Likely Linux / Unix / Android"
    assert d["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert d["open_ports"] == [22, 80]
    assert d["discovery_method"] == "ICMP ping"


def test_host_info_to_dict_dead_host_minimal():
    host = HostInfo(ip="192.168.1.100")
    d = host.to_dict()
    assert d["ip"] == "192.168.1.100"
    assert d["is_alive"] is False
    assert "hostname" not in d
    assert "ttl" not in d


def test_network_map_alive_hosts():
    nm = NetworkMap(subnet="10.0.0.0/24", scan_start=1000.0, scan_end=1005.0)
    nm.hosts = [
        HostInfo(ip="10.0.0.1", is_alive=True),
        HostInfo(ip="10.0.0.2", is_alive=False),
        HostInfo(ip="10.0.0.3", is_alive=True),
    ]
    assert len(nm.alive_hosts) == 2


def test_network_map_duration():
    nm = NetworkMap(subnet="10.0.0.0/24", scan_start=1000.0, scan_end=1003.75)
    assert nm.duration_seconds == 3.75


def test_network_map_to_dict():
    nm = NetworkMap(subnet="10.0.0.0/24", scan_start=1000.0, scan_end=1002.0)
    nm.hosts = [
        HostInfo(ip="10.0.0.1", is_alive=True),
        HostInfo(ip="10.0.0.2", is_alive=False),
    ]
    d = nm.to_dict()
    assert d["subnet"] == "10.0.0.0/24"
    assert d["total_hosts_scanned"] == 2
    assert d["alive_hosts_count"] == 1
    # Only alive hosts appear in the dict
    assert len(d["hosts"]) == 1


def test_guess_os_from_ttl_linux():
    assert NetworkMapper._guess_os_from_ttl(64) == "Likely Linux / Unix / Android"


def test_guess_os_from_ttl_windows():
    assert NetworkMapper._guess_os_from_ttl(128) == "Likely Windows / macOS / iOS"


def test_guess_os_from_ttl_unknown():
    # 256 is out of range for all defined fingerprints
    assert NetworkMapper._guess_os_from_ttl(256) == "Unknown"


def test_ttl_fingerprints_cover_full_range():
    """All TTL values 0-255 should map to some OS hint."""
    for ttl_val in range(256):
        result = NetworkMapper._guess_os_from_ttl(ttl_val)
        assert isinstance(result, str)
        assert len(result) > 0
