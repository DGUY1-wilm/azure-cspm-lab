# Azure CSPM Lab

<!-- [AI-generated outline] Claude, 2026-10-24. Sections get filled in as milestones complete. -->

Deliberately misconfigured Azure resources in my own subscription, detected with
Prowler, parsed into SQLite, prioritized, remediated, and re-scanned. It's the cloud
counterpart to my internal ASM pipeline.

> All resources were created by me, in my own Azure for Students subscription, for this
> project only. Nothing outside that subscription was scanned.

## Architecture
<!-- docs/architecture.png -->

## What was misconfigured (and why it matters)
<!-- Milestones 3 and 5 -->

## Findings and prioritization
<!-- Milestone 4: scoring approach, CIS Azure mapping -->

## Remediation and re-scan
<!-- Milestone 6: before/after -->

## Cost controls
See [docs/cost-controls.md](docs/cost-controls.md).

## Secret hygiene
- Prowler authenticates via my `az login` session, so no stored client secret
- Raw scans and databases are gitignored (they contain account identifiers)
- gitleaks runs as a pre-commit hook and in CI
- Screenshots are redacted before committing

## Running it
<!-- Setup steps, added as they're built -->

## Limitations
<!-- Be honest: single subscription, small environment, free tooling only, etc. -->

## AI usage
See [AI_USAGE.md](AI_USAGE.md).
