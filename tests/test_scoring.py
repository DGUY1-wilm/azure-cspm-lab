"""[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [x] pending"""
from cspm.scoring import score_finding
from conftest import SUB_UID


def row(check_id, uid=SUB_UID, severity="high"):
    return {"id": 1, "check_id": check_id, "severity": severity,
            "resource_name": "res", "resource_uid": uid}


def test_public_blob_is_p1_even_though_cmk_has_same_prowler_severity(rules):
    blob = score_finding(row("storage_blob_public_access_level_is_disabled"), rules)
    cmk = score_finding(row("storage_ensure_encryption_with_customer_managed_keys"), rules)
    assert (blob.tier, cmk.tier) == ("P1", "P4")


def test_root_scope_role_assignment_is_excluded(rules):
    uid = "/providers/Microsoft.Authorization/roleAssignments/fake"
    scored = score_finding(row("iam_role_user_access_admin_restricted", uid), rules)
    assert scored.tier == "excluded"
    assert scored.exposure_class == "out_of_scope"


def test_subscription_role_assignment_is_scored_not_excluded(rules):
    uid = f"{SUB_UID}/providers/Microsoft.Authorization/roleAssignments/fake"
    scored = score_finding(row("iam_role_user_access_admin_restricted", uid), rules)
    assert scored.tier == "P2"
    assert scored.tactic == "Privilege Escalation"


def test_unknown_check_is_flagged_unclassified(rules):
    assert score_finding(row("brand_new_prowler_check"), rules).tier == "unclassified"


def test_custom_nsg_check_tier_depends_on_attachment(rules):
    attached = score_finding(row("custom_nsg_ssh_open_to_internet"), rules)
    unattached = score_finding(row("custom_nsg_ssh_open_to_internet_unattached"), rules)
    assert (attached.tier, unattached.tier) == ("P1", "P2")


def test_every_rule_uses_a_defined_class(rules):
    for check_id, rule in rules["checks"].items():
        assert rule["class"] in rules["tiers"], check_id
