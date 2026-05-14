"""Unit tests for app.network.subnet_calc — pure stdlib, no fixtures."""
import pytest

from app.network import subnet_calc


def test_calc_ipv4_basic():
    r = subnet_calc.calc("192.168.1.0/24")
    assert r["network"] == "192.168.1.0"
    assert r["broadcast"] == "192.168.1.255"
    assert r["usable_hosts"] == 254
    assert r["usable_first"] == "192.168.1.1"
    assert r["usable_last"] == "192.168.1.254"
    assert r["is_private"] is True
    assert r["version"] == 4


def test_calc_normalises_host_to_network():
    r = subnet_calc.calc("192.168.1.10/24")
    assert r["cidr"] == "192.168.1.0/24"


def test_calc_slash_31_has_no_broadcast_reserve():
    r = subnet_calc.calc("10.0.0.0/31")
    assert r["usable_hosts"] == 2


def test_calc_ipv6_has_no_broadcast_field():
    r = subnet_calc.calc("2001:db8::/64")
    assert r["broadcast"] is None
    assert r["wildcard"] is None
    assert r["version"] == 6


def test_calc_rejects_garbage():
    with pytest.raises(ValueError):
        subnet_calc.calc("not a cidr")


def test_split_basic():
    r = subnet_calc.split("10.0.0.0/24", 26)
    assert r["expected_count"] == 4
    assert r["returned"] == 4
    assert r["truncated"] is False
    assert [s["cidr"] for s in r["subnets"]] == [
        "10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26",
    ]


def test_split_truncates_huge_request():
    r = subnet_calc.split("10.0.0.0/8", 32, max_subnets=10)
    assert r["truncated"] is True
    assert r["returned"] == 10


def test_split_rejects_smaller_prefix():
    with pytest.raises(ValueError):
        subnet_calc.split("10.0.0.0/24", 16)


def test_aggregate_collapses_contiguous():
    r = subnet_calc.aggregate([
        "192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24",
    ])
    assert r["supernets"] == ["192.168.0.0/22"]


def test_aggregate_handles_mixed_families():
    r = subnet_calc.aggregate(["10.0.0.0/24", "2001:db8::/64"])
    assert "10.0.0.0/24" in r["supernets"]
    assert "2001:db8::/64" in r["supernets"]


def test_aggregate_rejects_empty():
    assert subnet_calc.aggregate([]) == {"input": [], "supernets": []}
