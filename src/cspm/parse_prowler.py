"""Parse Prowler OCSF JSON output into normalized finding records.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending

Input:  one Prowler scan's *.ocsf.json file (a JSON array of findings).
Output: a ScanResult holding scan metadata and a list of Finding records.
This module only reads and validates. Storing results is db.py's job.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

VALID_STATUSES = {"PASS", "FAIL", "MANUAL"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


class ParseError(ValueError):
    """Raised when the input doesn't match the structure the parser expects."""


@dataclass(frozen=True)
class Finding:
    check_id: str
    status: str                       # PASS / FAIL / MANUAL (from status_code)
    severity: str                     # normalized to lowercase
    severity_id: int | None
    title: str
    status_detail: str
    risk: str
    remediation: str
    resource_uid: str
    resource_name: str
    resource_type: str
    resource_group: str
    region: str
    compliance: dict[str, list[str]]  # framework -> list of control IDs


@dataclass(frozen=True)
class ScanResult:
    scan_id: str
    scanned_at: str
    prowler_version: str
    findings: list[Finding]


def _get(obj: dict, path: str, index: int, required: bool = True, default=None):
    """Follow a dotted path like 'metadata.event_code' through nested dicts.

    Required fields raise ParseError if missing or null; optional ones
    return `default` instead.
    """
    current = obj
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            if required:
                raise ParseError(f"finding #{index}: missing required field '{path}'")
            return default
        current = current[key]
    if current is None:
        if required:
            raise ParseError(f"finding #{index}: required field '{path}' is null")
        return default
    return current


def parse_finding(raw: dict, index: int) -> Finding:
    """Turn one raw OCSF finding into a validated Finding."""
    resources = _get(raw, "resources", index)
    if not isinstance(resources, list) or len(resources) != 1:
        count = len(resources) if isinstance(resources, list) else "non-list"
        raise ParseError(f"finding #{index}: expected exactly 1 resource, got {count}")
    resource = resources[0]

    status = str(_get(raw, "status_code", index)).upper()
    if status not in VALID_STATUSES:
        raise ParseError(f"finding #{index}: unexpected status_code '{status}'")

    severity = str(_get(raw, "severity", index)).lower()
    if severity not in VALID_SEVERITIES:
        raise ParseError(f"finding #{index}: unexpected severity '{severity}'")

    compliance = _get(raw, "unmapped.compliance", index, required=False, default={})

    return Finding(
        check_id=_get(raw, "metadata.event_code", index),
        status=status,
        severity=severity,
        severity_id=_get(raw, "severity_id", index, required=False),
        title=_get(raw, "finding_info.title", index, required=False, default=""),
        status_detail=_get(raw, "status_detail", index, required=False, default=""),
        risk=_get(raw, "risk_details", index, required=False, default=""),
        remediation=_get(raw, "remediation.desc", index, required=False, default=""),
        resource_uid=_get(resource, "uid", index),
        resource_name=_get(resource, "name", index, required=False, default=""),
        resource_type=_get(resource, "type", index, required=False, default=""),
        resource_group=_get(resource, "group.name", index, required=False, default=""),
        region=_get(resource, "region", index, required=False, default=""),
        compliance={fw: list(controls) for fw, controls in compliance.items()},
    )


def parse_scan(path: str | Path) -> ScanResult:
    """Parse a whole OCSF file. All findings must belong to one scan."""
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        raise ParseError("expected a JSON array of findings")
    if not data:
        raise ParseError("file contains no findings")

    findings = [parse_finding(raw, i) for i, raw in enumerate(data)]

    scan_ids = {_get(raw, "unmapped.scan_id", i) for i, raw in enumerate(data)}
    if len(scan_ids) != 1:
        raise ParseError(f"expected one scan_id per file, found {len(scan_ids)}")

    first = data[0]
    return ScanResult(
        scan_id=scan_ids.pop(),
        scanned_at=_get(first, "time_dt", 0, required=False, default=""),
        prowler_version=_get(first, "metadata.product.version", 0, required=False, default=""),
        findings=findings,
    )


def main() -> None:
    """Print a safe summary (counts only, no IDs) for a quick sanity check."""
    result = parse_scan(sys.argv[1])
    print(f"Prowler {result.prowler_version}, scanned {result.scanned_at}")
    print(f"Findings: {len(result.findings)}")
    print("Status:  ", dict(Counter(f.status for f in result.findings)))
    print("Severity:", dict(Counter(f.severity for f in result.findings)))


if __name__ == "__main__":
    main()
