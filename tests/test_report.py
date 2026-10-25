"""[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending"""
from cspm.report import EMAIL, GUID, build_report, redact
from conftest import FAKE_SUB, SUB_UID, make_finding


def test_redact_removes_guids_emails_and_escapes_html():
    text = f"sub ({FAKE_SUB}) owner someone@example.edu <script>"
    out = redact(text)
    assert FAKE_SUB not in out and "example.edu" not in out
    assert "<script>" not in out and "&lt;script&gt;" in out


def test_full_report_contains_no_identifiers(db, load, rules):
    detail = f"Storage account x from subscription Lab ({FAKE_SUB}), contact a@example.edu"
    load([make_finding("storage_blob_public_access_level_is_disabled",
                       uid=f"{SUB_UID}/sa", scan_id="scan-a", detail=detail)], "before")
    page = build_report(db, rules)
    assert not GUID.findall(page)
    assert not EMAIL.findall(page)
    assert "P1" in page
