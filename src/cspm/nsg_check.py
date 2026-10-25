"""Custom NSG check covering a confirmed Prowler false negative.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending

Why this exists: Prowler 5.45.0's network_ssh/rdp_internet_access_restricted checks
read only a rule's singular destination port field. Azure stores multi-port rules in
the plural field, so a rule opening "22 3389" to the internet passed. This check
reads both singular and plural port and source fields, and treats "*" as every port.
It also records whether the NSG is attached, so live exposure scores higher than latent.

Input: the JSON from `az network nsg list --resource-group <rg> -o json`.
Usage (from the repo root, with PYTHONPATH=src):
    python -m cspm.nsg_check --label after-nsg-experiment --input scans\\after-nsg-experiment\\nsg_rules.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cspm.db import DEFAULT_DB, connect, store_custom_findings
from cspm.parse_prowler import Finding

INTERNET_SOURCES = {"*", "internet", "any", "0.0.0.0", "0.0.0.0/0", "::/0", "/0"}
WATCHED_PORTS = {"ssh": 22, "rdp": 3389}


def _values(rule: dict, singular: str, plural: str) -> list[str]:
    """Combine a rule's singular and plural fields into one list (the Prowler gap)."""
    values = [str(v) for v in (rule.get(plural) or [])]
    if rule.get(singular):
        values.append(str(rule[singular]))
    return values


def port_matches(spec: str, port: int) -> bool:
    """True if a port spec ("22", "20-25", or "*") covers the given port."""
    spec = spec.strip()
    if spec == "*":
        return True
    if "-" in spec:
        low, high = spec.split("-", 1)
        return int(low) <= port <= int(high)
    return spec.isdigit() and int(spec) == port


def exposing_rules(nsg: dict, port: int) -> list[str]:
    """Names of inbound Allow rules that open `port` to the internet."""
    names = []
    for rule in nsg.get("securityRules") or []:
        if rule.get("direction") != "Inbound" or rule.get("access") != "Allow":
            continue
        if str(rule.get("protocol", "")).lower() not in {"tcp", "*"}:
            continue
        sources = [s.lower() for s in _values(rule, "sourceAddressPrefix", "sourceAddressPrefixes")]
        if not any(s in INTERNET_SOURCES for s in sources):
            continue
        ports = _values(rule, "destinationPortRange", "destinationPortRanges")
        if any(port_matches(p, port) for p in ports):
            names.append(rule.get("name", "?"))
    return names


def evaluate_nsgs(nsgs: list[dict]) -> list[Finding]:
    """One PASS/FAIL finding per NSG per watched port. Pure function, easy to test."""
    findings = []
    for nsg in nsgs:
        attached = bool(nsg.get("networkInterfaces") or nsg.get("subnets"))
        for service, port in WATCHED_PORTS.items():
            rules = exposing_rules(nsg, port)
            label = service.upper()
            if rules:
                detail = f"Rule(s) {', '.join(rules)} allow {label} (port {port}) from the internet"
            else:
                detail = f"No inbound rule allows {label} (port {port}) from the internet"
            if not attached:
                detail += "; NSG is not attached to any NIC or subnet"

            findings.append(Finding(
                check_id=f"custom_nsg_{service}_open_to_internet" + ("" if attached else "_unattached"),
                status="FAIL" if rules else "PASS",
                severity="high",
                severity_id=4,
                title=f"NSG does not allow {label} from the internet (custom check)",
                status_detail=detail,
                risk=f"Internet-wide {label} access invites brute force and exploitation of the management service",
                remediation="Remove the rule or restrict its source to specific trusted IP ranges",
                resource_uid=nsg["id"],
                resource_name=nsg.get("name", ""),
                resource_type="Microsoft.Network/networkSecurityGroups",
                resource_group=nsg.get("resourceGroup", ""),
                region=nsg.get("location", ""),
                compliance={},
            ))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the custom NSG check and store results.")
    parser.add_argument("--label", required=True, help="existing scan label to attach findings to")
    parser.add_argument("--input", required=True, help="JSON from az network nsg list")
    parser.add_argument("--db", default=DEFAULT_DB)
    args = parser.parse_args()

    text = Path(args.input).read_text(encoding="utf-8-sig")
    if not text.strip():
        raise SystemExit(f"{args.input} is empty; did the 'az network nsg list' command fail?")
    nsgs = json.loads(text)
    findings = evaluate_nsgs(nsgs)

    conn = connect(args.db)
    try:
        stored = store_custom_findings(conn, args.label, findings)
    finally:
        conn.close()

    for f in findings:
        print(f"{f.status:<5} {f.check_id:<45} {f.resource_name}")
    print(f"\n{len(nsgs)} NSG(s) evaluated; "
          + (f"{len(findings)} findings stored under '{args.label}'" if stored
             else f"custom findings already stored for '{args.label}', skipped"))


if __name__ == "__main__":
    main()