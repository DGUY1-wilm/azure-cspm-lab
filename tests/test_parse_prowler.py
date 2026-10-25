"""[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [x] pending"""
import pytest

from cspm.parse_prowler import ParseError, parse_scan
from conftest import make_finding


def test_counts_and_status_come_from_status_code(write_scan):
    # Every real finding has status "New"; pass/fail lives in status_code.
    findings = [make_finding("a", "FAIL"), make_finding("b", "PASS"), make_finding("c", "FAIL")]
    result = parse_scan(write_scan(findings))
    assert len(result.findings) == 3
    assert [f.status for f in result.findings] == ["FAIL", "PASS", "FAIL"]


def test_severity_is_normalized_to_lowercase(write_scan):
    result = parse_scan(write_scan([make_finding("a", severity="High")]))
    assert result.findings[0].severity == "high"


def test_reads_utf8_file_with_bom(tmp_path):
    import json
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps([make_finding("a")]).encode())
    assert len(parse_scan(path).findings) == 1


@pytest.mark.parametrize("resources", [[], [{"uid": "x"}, {"uid": "y"}]])
def test_rejects_findings_without_exactly_one_resource(write_scan, resources):
    finding = make_finding("a")
    finding["resources"] = resources
    with pytest.raises(ParseError, match="exactly 1 resource"):
        parse_scan(write_scan([finding]))


def test_rejects_missing_required_field(write_scan):
    finding = make_finding("a")
    del finding["metadata"]["event_code"]
    with pytest.raises(ParseError, match="metadata.event_code"):
        parse_scan(write_scan([finding]))


def test_rejects_unknown_status(write_scan):
    with pytest.raises(ParseError, match="status_code"):
        parse_scan(write_scan([make_finding("a", status="MAYBE")]))


def test_rejects_empty_file(write_scan):
    with pytest.raises(ParseError, match="no findings"):
        parse_scan(write_scan([]))


def test_rejects_mixed_scan_ids(write_scan):
    findings = [make_finding("a", scan_id="scan-a"), make_finding("b", scan_id="scan-b")]
    with pytest.raises(ParseError, match="one scan_id"):
        parse_scan(write_scan(findings))


def test_missing_optional_fields_default_to_empty(write_scan):
    finding = make_finding("a")
    del finding["finding_info"]
    result = parse_scan(write_scan([finding]))
    assert result.findings[0].title == ""
