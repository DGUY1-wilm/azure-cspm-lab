"""Prioritize stored findings using my own exposure-based rules.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending

Tiers come from config/check_rules.toml, not from Prowler's severity labels.
Scores are computed when read, never stored, so changing a rule re-scores
every scan without reloading anything.

Usage (from the repo root, with PYTHONPATH=src):
    python -m cspm.scoring --label after-public-blob
"""
from __future__ import annotations

import argparse
import sqlite3
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from cspm.db import DEFAULT_DB, connect

DEFAULT_RULES = Path("config") / "check_rules.toml"

TIER_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "unclassified": 4, "excluded": 5}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
SCORED_STATUSES = ("FAIL", "MANUAL")  # PASS findings need no action


@dataclass(frozen=True)
class ScoredFinding:
    finding_id: int
    check_id: str
    severity: str
    resource_name: str
    tier: str            # P1-P4, "unclassified", or "excluded"
    exposure_class: str  # e.g. direct_exposure; exclusion category if excluded
    tactic: str          # my ATT&CK tactic, or "" if none
    reason: str          # why this tier (or why excluded)


def load_rules(path: str | Path = DEFAULT_RULES) -> dict:
    """Read the TOML rules file (tomllib needs it opened in binary mode)."""
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _matching_exclusion(finding: dict, rules: dict) -> dict | None:
    for rule in rules.get("exclusions", []):
        if rule["check_id"] != finding["check_id"]:
            continue
        prefix = rule.get("resource_prefix")
        if prefix is None or finding["resource_uid"].startswith(prefix):
            return rule
    return None


def score_finding(finding: dict, rules: dict) -> ScoredFinding:
    """Assign a tier to one finding. Pure function: no database, easy to test."""
    common = dict(
        finding_id=finding["id"],
        check_id=finding["check_id"],
        severity=finding["severity"],
        resource_name=finding["resource_name"] or "",
    )

    exclusion = _matching_exclusion(finding, rules)
    if exclusion:
        return ScoredFinding(**common, tier="excluded", exposure_class=exclusion["category"],
                             tactic="", reason=exclusion["reason"])

    check_rule = rules.get("checks", {}).get(finding["check_id"])
    if check_rule is None:
        return ScoredFinding(**common, tier="unclassified", exposure_class="",
                             tactic="", reason="No rule for this check; review and classify")

    exposure_class = check_rule["class"]
    return ScoredFinding(**common, tier=rules["tiers"][exposure_class],
                         exposure_class=exposure_class,
                         tactic=check_rule.get("tactic", ""),
                         reason=check_rule.get("why", ""))


def sort_key(s: ScoredFinding) -> tuple:
    """Tier first, then Prowler severity as the tie-breaker, then check name."""
    return (TIER_ORDER[s.tier], SEVERITY_ORDER.get(s.severity, 99), s.check_id)


def score_scan(conn: sqlite3.Connection, label: str, rules: dict) -> list[ScoredFinding]:
    """Score every FAIL/MANUAL finding in the scan with this label."""
    rows = conn.execute(
        "SELECT f.* FROM findings f JOIN scans s ON s.scan_id = f.scan_id "
        f"WHERE s.label = ? AND f.status IN ({','.join('?' * len(SCORED_STATUSES))})",
        (label, *SCORED_STATUSES),
    ).fetchall()
    return sorted((score_finding(dict(r), rules) for r in rows), key=sort_key)


def main() -> None:
    parser = argparse.ArgumentParser(description="Show prioritized findings for one scan.")
    parser.add_argument("--label", required=True)
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--rules", default=DEFAULT_RULES)
    args = parser.parse_args()

    conn = connect(args.db)
    try:
        scored = score_scan(conn, args.label, load_rules(args.rules))
    finally:
        conn.close()

    if not scored:
        print(f"No FAIL/MANUAL findings for label '{args.label}' (check the label name)")
        return
    for s in scored:
        print(f"{s.tier:<13} {s.severity:<8} {s.check_id:<62} {s.tactic}")
    print("\nTier counts:", dict(Counter(s.tier for s in scored)))


if __name__ == "__main__":
    main()
