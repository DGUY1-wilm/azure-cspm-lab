# Baseline Triage

<!-- [AI-generated] Claude, 2026-10-24; updated 2026-10-25. Reviewed by Daniel: [x] pending -->

Scan: Prowler 5.45.0, Azure for Students subscription, Entra checks excluded, before any lab
resources were deployed. **21 FAIL / 2 PASS.**

These decisions were later encoded in `config/check_rules.toml`: "Fix" findings became scored
tiers, and "Accept", "Not applicable", and "Out of scope" became exclusions with these reasons.

| Check ID | Prowler severity | Group | Reason |
|---|---|---|---|
| monitor_alert_create_update_nsg | high | Fix | NSG changes alter what's reachable from the internet |
| monitor_alert_delete_nsg | high | Fix | Deleting an NSG can expose resources |
| monitor_alert_create_update_public_ip_address_rule | medium | Fix | A new public IP is new internet-facing attack surface |
| monitor_alert_delete_public_ip_address_rule | medium | Fix | Paired with the create/update alert |
| monitor_alert_create_policy_assignment | medium | Fix | Policy changes can weaken guardrails |
| monitor_alert_delete_policy_assignment | high | Fix | Deleting a policy removes a guardrail |
| monitor_alert_create_update_security_solution | medium | Fix | Detects changes to security tooling |
| monitor_alert_delete_security_solution | medium | Fix | Detects removal of security tooling |
| monitor_alert_service_health_exists | medium | Fix | Visibility into Azure-side incidents |
| monitor_diagnostic_settings_exists | high | Fix (pending cost check) | Activity log should be retained; destination affects cost |
| monitor_diagnostic_setting_with_appropriate_categories | high | Fix (pending cost check) | Resolved by the same diagnostic setting |
| monitor_alert_create_update_sqlserver_fr | medium | Not applicable | No SQL servers in this lab; would be Fix in production |
| monitor_alert_delete_sqlserver_fr | medium | Not applicable | Same as above |
| defender_ensure_mcas_is_enabled | medium | Accept (cost) | Defender for Cloud Apps requires a paid license |
| defender_ensure_wdatp_is_enabled | high | Not applicable | Defender for Endpoint protects VMs/servers; the lab has none (and it's paid) |
| defender_ensure_iot_hub_defender_is_on | high | Not applicable | No IoT Hub exists |
| appinsights_ensure_is_configured | low | Not applicable | No application to monitor |
| network_bastion_host_exists | medium | Not applicable | No VMs to reach; Bastion is billed hourly |
| network_watcher_enabled | high | Partial | Could enable in westus2, where lab resources live; the check would still fail because it requires every region |
| iam_role_user_access_admin_restricted (x2) | high | Out of scope | Inherited from the root scope (no /subscriptions prefix); owned by university IT, not this lab |

## Summary
- Fix: 11 (9 activity log alerts + 1 diagnostic setting that resolves 2 findings)
- Accept (cost): 1
- Not applicable: 6
- Partial: 1
- Out of scope: 2

## Outcome
- Fixed during the project: the two NSG alert checks (verified by triggering both alerts).
- Not fixed: the other 7 alert checks and the 2 diagnostic setting checks. They stayed P3 to
  keep the lab small.
- Network Watcher: scored as P3 rather than excluded; not enabled.

## Takeaway
None of the 21 baseline failures is an exposed resource. They are missing *detective* controls
(alerts, logging), unused paid services, or inherited settings. Prowler rated 8 of them high;
after context, the most important are the NSG and public IP change alerts, because they detect
changes to internet-facing attack surface.
