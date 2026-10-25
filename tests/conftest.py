"""Shared synthetic test data. No real scan data: all IDs and emails are fake.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending
"""
import json
from pathlib import Path

import pytest

from cspm.db import connect, store_scan
from cspm.parse_prowler import parse_scan
from cspm.scoring import load_rules

FAKE_SUB = "00000000-0000-0000-0000-000000000000"
SUB_UID = f"/subscriptions/{FAKE_SUB}"
RULES_PATH = Path(__file__).resolve().parents[1] / "config" / "check_rules.toml"


def make_finding(check_id, status="FAIL", severity="High", uid=SUB_UID,
                 scan_id="scan-a", name="res", detail=""):
    """Build one OCSF-shaped finding with only the fields the parser reads."""
    return {
        "status_code": status,
        "status": "New",
        "severity": severity,
        "severity_id": 4,
        "status_detail": detail,
        "metadata": {"event_code": check_id, "product": {"version": "5.45.0"}},
        "finding_info": {"title": f"title for {check_id}"},
        "resources": [{"uid": uid, "name": name, "region": "westus2"}],
        "unmapped": {"scan_id": scan_id, "compliance": {"CIS-5.0": ["1.1"]}},
        "time_dt": f"2026-01-01T00:00:0{ord(scan_id[-1]) % 10}",
    }


@pytest.fixture
def write_scan(tmp_path):
    """Write a list of findings to an OCSF-style JSON file and return its path."""
    def _write(findings, name="scan.ocsf.json"):
        path = tmp_path / name
        path.write_text(json.dumps(findings), encoding="utf-8")
        return path
    return _write


@pytest.fixture
def rules():
    """The real rules file, so tests also prove it parses."""
    return load_rules(RULES_PATH)


@pytest.fixture
def db(tmp_path):
    conn = connect(tmp_path / "test.db")
    yield conn
    conn.close()


@pytest.fixture
def load(db, write_scan):
    """Parse and store a list of findings under a label."""
    def _load(findings, label):
        store_scan(db, parse_scan(write_scan(findings, f"{label}.json")), label)
    return _load
