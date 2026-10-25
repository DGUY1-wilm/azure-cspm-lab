# Cost Controls

<!-- [AI-generated template] Claude, 2026-10-24. Fill in with your own words and real details. -->

## Subscription
- Offer type: Azure for Students (credit-based, no credit card attached)
- Rule: never upgrade to pay-as-you-go

## Guardrails set up before deploying anything
- Budget: `cspm-lab-budget`, $5/month, alerts at 50% and 100% actual, 80% forecasted
  - Budgets only alert; they don't stop spending. The hard stop is the credit limit.
- Defender for Cloud: paid plans confirmed Off (Foundational CSPM only)
- All project resources confined to one resource group: `rg-cspm-lab`
- No VMs: every misconfiguration is shown on free or near-free resources

## Teardown
<!-- Fill in at milestone 9: commands run, and proof of no remaining resources/spend. -->
