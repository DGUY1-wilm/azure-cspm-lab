"""Compare two stored scans: which failing findings are new, fixed, gone, or persisting.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [x] pending

Finding identity across scans is (check_id, resource_uid).
  new        - failing in the later scan, not failing in the earlier one
  fixed      - failing earlier; same check + resource now PASSES (remediated)
  gone       - failing earlier; check + resource absent later (e.g. resource deleted)
  Exception: "does X exist?" checks fail on the subscription itself but pass on the
  resource that satisfies them (e.g. the new alert rule). A subscription-level failure
  that disappears while the same check now PASSES is counted as fixed, not gone.
  persisting - failing in both

Usage (from the repo root, with PYTHONPATH=src):
    python -m cspm.diff --before after-public-blob --after after-remediation
"""
from __future__ import annotations

import argparse
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass

from cspm.db import DEFAULT_DB, connect
from cspm.scoring import DEFAULT_RULES, TIER_ORDER, load_rules, score_finding

FAILING = ("FAIL", "MANUAL")
SUBSCRIPTION_UID = re.compile(r"^/subscriptions/[^/]+$", re.IGNORECASE)


@dataclass(frozen=True)
class Change:
    change: str        # new / fixed / gone / persisting
    tier: str          # scored with the current rules
    check_id: str
    resource_name: str


def _findings_by_identity(conn: sqlite3.Connection, label: str) -> dict[tuple, dict]:
    rows = conn.execute(
        "SELECT f.* FROM findings f JOIN scans s ON s.scan_id = f.scan_id WHERE s.label = ?",
        (label,),
    ).fetchall()
    if not rows:
        raise ValueError(f"No findings stored for label '{label}'")
    return {(r["check_id"], r["resource_uid"]): dict(r) for r in rows}


def compare(conn: sqlite3.Connection, before: str, after: str, rules: dict) -> list[Change]:
    old = _findings_by_identity(conn, before)
    new = _findings_by_identity(conn, after)
    changes = []
    passing_checks_later = {f["check_id"] for f in new.values() if f["status"] == "PASS"}

    for key, finding in old.items():
        if finding["status"] not in FAILING:
            continue
        later = new.get(key)
        if later is None:
            subscription_level = bool(SUBSCRIPTION_UID.match(finding["resource_uid"]))
            if subscription_level and finding["check_id"] in passing_checks_later:
                kind, source = "fixed", finding
            else:
                kind, source = "gone", finding
        elif later["status"] in FAILING:
            kind, source = "persisting", later
        else:
            kind, source = "fixed", finding
        changes.append(_change(kind, source, rules))

    for key, finding in new.items():
        was = old.get(key)
        if finding["status"] in FAILING and (was is None or was["status"] not in FAILING):
            changes.append(_change("new", finding, rules))

    order = {"new": 0, "fixed": 1, "gone": 2, "persisting": 3}
    return sorted(changes, key=lambda c: (order[c.change], TIER_ORDER[c.tier], c.check_id))


def _change(kind: str, finding: dict, rules: dict) -> Change:
    scored = score_finding(finding, rules)
    return Change(kind, scored.tier, scored.check_id, scored.resource_name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare two stored scans.")
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--rules", default=DEFAULT_RULES)
    parser.add_argument("--all", action="store_true", help="also list persisting findings")
    args = parser.parse_args()

    conn = connect(args.db)
    try:
        changes = compare(conn, args.before, args.after, load_rules(args.rules))
    finally:
        conn.close()

    for c in changes:
        if c.change != "persisting" or args.all:
            print(f"{c.change:<11} {c.tier:<13} {c.check_id}")
    print(f"\n{args.before} -> {args.after}:", dict(Counter(c.change for c in changes)))


if __name__ == "__main__":
    main()
