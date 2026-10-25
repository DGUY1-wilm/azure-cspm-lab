"""Store parsed Prowler scans in SQLite.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending

Usage (from the repo root, with PYTHONPATH=src):
    python -m cspm.db load <ocsf.json> --label baseline
    python -m cspm.db stats
"""
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

from cspm.parse_prowler import ScanResult, parse_scan

DEFAULT_DB = Path("data") / "cspm.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id         TEXT PRIMARY KEY,
    label           TEXT NOT NULL UNIQUE,
    scanned_at      TEXT NOT NULL,
    prowler_version TEXT,
    finding_count   INTEGER NOT NULL,
    loaded_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY,
    scan_id        TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    check_id       TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('PASS', 'FAIL', 'MANUAL')),
    severity       TEXT NOT NULL,
    severity_id    INTEGER,
    title          TEXT,
    status_detail  TEXT,
    risk           TEXT,
    remediation    TEXT,
    resource_uid   TEXT NOT NULL,
    resource_name  TEXT,
    resource_type  TEXT,
    resource_group TEXT,
    region         TEXT,
    UNIQUE (scan_id, check_id, resource_uid)
);

CREATE TABLE IF NOT EXISTS compliance (
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    framework  TEXT NOT NULL,
    control    TEXT NOT NULL,
    PRIMARY KEY (finding_id, framework, control)
);

-- Finding identity across scans is (check_id, resource_uid); index it for scan diffs.
CREATE INDEX IF NOT EXISTS idx_findings_identity ON findings (check_id, resource_uid);
"""


def connect(db_path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    """Open the database, create tables if needed, and enforce foreign keys."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def store_scan(conn: sqlite3.Connection, result: ScanResult, label: str) -> bool:
    """Insert one scan and its findings. Returns False if the scan was already loaded."""
    already = conn.execute(
        "SELECT 1 FROM scans WHERE scan_id = ?", (result.scan_id,)
    ).fetchone()
    if already:
        return False

    with conn:  # one transaction: the whole scan loads, or none of it does
        conn.execute(
            "INSERT INTO scans (scan_id, label, scanned_at, prowler_version, finding_count) "
            "VALUES (?, ?, ?, ?, ?)",
            (result.scan_id, label, result.scanned_at, result.prowler_version,
             len(result.findings)),
        )
        for f in result.findings:
            cur = conn.execute(
                "INSERT INTO findings (scan_id, check_id, status, severity, severity_id, "
                "title, status_detail, risk, remediation, resource_uid, resource_name, "
                "resource_type, resource_group, region) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result.scan_id, f.check_id, f.status, f.severity, f.severity_id,
                 f.title, f.status_detail, f.risk, f.remediation, f.resource_uid,
                 f.resource_name, f.resource_type, f.resource_group, f.region),
            )
            conn.executemany(
                "INSERT OR IGNORE INTO compliance (finding_id, framework, control) "
                "VALUES (?, ?, ?)",
                [(cur.lastrowid, fw, control)
                 for fw, controls in f.compliance.items() for control in controls],
            )
    return True


def print_stats(conn: sqlite3.Connection) -> None:
    """Per-scan counts straight from the database (no IDs printed)."""
    rows = conn.execute(
        "SELECT s.label, s.scanned_at, s.finding_count, "
        "       SUM(f.status = 'FAIL') AS fails, SUM(f.status = 'PASS') AS passes, "
        "       COUNT(f.id) AS stored "
        "FROM scans s LEFT JOIN findings f ON f.scan_id = s.scan_id "
        "GROUP BY s.scan_id ORDER BY s.scanned_at"
    ).fetchall()
    for r in rows:
        print(f"{r['label']:<20} {r['scanned_at']:<28} "
              f"stored={r['stored']}/{r['finding_count']} FAIL={r['fails']} PASS={r['passes']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Load Prowler scans into SQLite.")
    parser.add_argument("--db", default=DEFAULT_DB, help="database path (default: data/cspm.db)")
    sub = parser.add_subparsers(dest="command", required=True)

    load = sub.add_parser("load", help="parse an OCSF file and store it")
    load.add_argument("path")
    load.add_argument("--label", required=True, help="short name, e.g. baseline")
    sub.add_parser("stats", help="show per-scan counts")

    args = parser.parse_args()
    conn = connect(args.db)
    try:
        if args.command == "load":
            result = parse_scan(args.path)
            if store_scan(conn, result, args.label):
                print(f"Loaded {len(result.findings)} findings as '{args.label}'")
            else:
                print(f"Scan already loaded; skipped '{args.label}'")
        else:
            print_stats(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
