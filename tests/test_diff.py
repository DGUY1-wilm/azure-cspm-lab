"""[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [x] pending"""
from cspm.diff import compare
from conftest import SUB_UID, make_finding


def changes(db, rules):
    return {(c.change, c.check_id) for c in compare(db, "before", "after", rules)}


def test_new_fixed_persisting(db, load, rules):
    blob, nsg_alert = "storage_blob_public_access_level_is_disabled", "monitor_alert_delete_nsg"
    sa = f"{SUB_UID}/storageAccounts/sa"
    load([make_finding(blob, uid=sa, scan_id="scan-a"),
          make_finding(nsg_alert, scan_id="scan-a")], "before")
    load([make_finding(blob, "PASS", uid=sa, scan_id="scan-b"),
          make_finding(nsg_alert, scan_id="scan-b"),
          make_finding("storage_key_rotation_90_days", uid=sa, scan_id="scan-b")], "after")
    assert changes(db, rules) == {
        ("fixed", blob), ("persisting", nsg_alert), ("new", "storage_key_rotation_90_days")}


def test_existence_check_fixed_by_new_resource_counts_as_fixed(db, load, rules):
    # Fails on the subscription itself, passes on the alert rule that now exists.
    check = "monitor_alert_delete_nsg"
    load([make_finding(check, scan_id="scan-a")], "before")
    load([make_finding(check, "PASS", uid=f"{SUB_UID}/activityLogAlerts/a", scan_id="scan-b")], "after")
    assert changes(db, rules) == {("fixed", check)}


def test_deleted_resource_is_gone_not_fixed(db, load, rules):
    # A different resource passing must not count as fixing a deleted one.
    check = "storage_geo_redundant_enabled"
    load([make_finding(check, uid=f"{SUB_UID}/sa1", scan_id="scan-a")], "before")
    load([make_finding(check, "PASS", uid=f"{SUB_UID}/sa2", scan_id="scan-b")], "after")
    assert changes(db, rules) == {("gone", check)}
