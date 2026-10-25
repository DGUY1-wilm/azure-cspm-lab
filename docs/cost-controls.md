# Cost Controls

<!-- [AI-drafted from my notes] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending -->

**Final spend for the whole project: less than $0.01** (Azure Cost Management, checked after teardown).

## Subscription
- Offer type: Azure for Students (credit-based, no credit card attached)
- Rule: never upgrade to pay-as-you-go. If the credit ran out, Azure would disable resources rather than bill me.

## Guardrails set up before deploying anything
- Budget: `cspm-lab-budget`, $5/month, alerts at 50% and 100% actual, 80% forecasted
  - Budgets only alert; they don't stop spending. The hard stop is the credit limit.
- Defender for Cloud: paid plans confirmed Off (Foundational CSPM only)
- All project resources confined to one resource group: `rg-cspm-lab`
- No VMs: every misconfiguration is shown on free or near-free resources

## Region
- The subscription has a Microsoft-managed "Allowed resource deployment regions" policy (effect: Deny)
  limiting deployments to `westus2` and `westus3`.
- All lab resources were deployed in **westus2**. The resource group itself was created in `eastus`;
  a resource group's location only stores its metadata, so this didn't affect the lab.

## What I deployed and what it cost
| Resource | Cost |
|---|---|
| Storage account (Standard LRS) with one small text file | Fractions of a cent (billed per GB stored) |
| Network security group and rules | Free |
| User-assigned managed identity and role assignment | Free |
| Two activity log alert rules | Free |
| Action group (email notifications) | Free within the monthly email allowance |

## Cost-driven decisions
- **Defender paid plans:** left off; the related findings are excluded as accepted cost.
- **Azure Bastion:** never deployed (billed hourly); finding excluded as not applicable.
- **Public snapshot scenario:** dropped, because snapshots need billable managed disks.
- **Diagnostic settings (log export):** not created, since cost depends on the log destination.

## Teardown
1. Ran `infra/teardown.ps1`, which listed every resource in `rg-cspm-lab` and required typing the
   resource group name to confirm.
2. The script removes any role assignments held by the lab's managed identities **before** deleting
   anything, so no orphaned assignments are left behind. (The lab identity's assignment had already
   been removed during remediation.)
3. Deleted the whole resource group: storage account, NSG, managed identity, alert rules, and action group.
4. Verified the resource group no longer exists and no lab resources remain.
5. Ran a final scan (`after-teardown`): 23 findings, 21 FAIL / 2 PASS, the same as the baseline.
   This confirms the account was back to its starting state.

**Lesson from teardown:** the two activity log alerts lived inside the lab's resource group, so
deleting the lab also deleted the monitoring. The final scan flagged both alert checks as failing again.
