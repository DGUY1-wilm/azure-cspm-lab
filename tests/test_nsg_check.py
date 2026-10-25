"""Tests for the custom NSG check that covers Prowler's multi-port false negative.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [x] pending
"""
import pytest

from cspm.nsg_check import evaluate_nsgs, main, port_matches


def nsg(rules, attached=False):
    return {"id": "/subscriptions/fake/nsg", "name": "nsg", "location": "westus2",
            "networkInterfaces": [{"id": "nic"}] if attached else None, "subnets": None,
            "securityRules": rules}


def rule(**overrides):
    base = {"name": "r", "access": "Allow", "direction": "Inbound", "protocol": "Tcp",
            "sourceAddressPrefix": "*", "sourceAddressPrefixes": [],
            "destinationPortRange": None, "destinationPortRanges": []}
    return {**base, **overrides}


def statuses(nsgs):
    return {f.check_id: f.status for f in evaluate_nsgs(nsgs)}


def test_multi_port_rule_is_detected():
    # The exact rule Prowler 5.45.0 passed: ports in the plural field only.
    result = statuses([nsg([rule(destinationPortRanges=["22", "3389"])])])
    assert result["custom_nsg_ssh_open_to_internet_unattached"] == "FAIL"
    assert result["custom_nsg_rdp_open_to_internet_unattached"] == "FAIL"


def test_single_port_rule_is_detected():
    result = statuses([nsg([rule(destinationPortRange="3389")])])
    assert result["custom_nsg_rdp_open_to_internet_unattached"] == "FAIL"
    assert result["custom_nsg_ssh_open_to_internet_unattached"] == "PASS"


def test_all_ports_and_plural_sources_are_detected():
    r = rule(sourceAddressPrefix=None, sourceAddressPrefixes=["10.0.0.0/8", "Internet"],
             destinationPortRange="*", protocol="*")
    result = statuses([nsg([r], attached=True)])
    assert result["custom_nsg_ssh_open_to_internet"] == "FAIL"


def test_restricted_source_and_deny_rules_pass():
    rules = [rule(sourceAddressPrefix="203.0.113.0/24", destinationPortRange="22"),
             rule(access="Deny", destinationPortRange="*")]
    assert set(statuses([nsg(rules)]).values()) == {"PASS"}


def test_attachment_changes_the_check_id():
    attached = statuses([nsg([rule(destinationPortRange="22")], attached=True)])
    assert "custom_nsg_ssh_open_to_internet" in attached


@pytest.mark.parametrize("spec,port,expected", [
    ("22", 22, True), ("2222", 22, False), ("20-25", 22, True),
    ("23-30", 22, False), ("*", 3389, True),
])
def test_port_matches(spec, port, expected):
    assert port_matches(spec, port) is expected


def test_empty_input_file_fails_loudly(tmp_path, monkeypatch):
    # A failed `az` export once produced an empty file; it must stop with a clear message.
    empty = tmp_path / "nsg_rules.json"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["nsg_check", "--label", "x", "--input", str(empty),
                                     "--db", str(tmp_path / "t.db")])
    with pytest.raises(SystemExit, match="is empty"):
        main()
