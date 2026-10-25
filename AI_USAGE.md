# AI Usage Log

I used Claude (Anthropic) as a pair-programming mentor on this project. This log records what
was AI-generated, what I did myself, and how I verified it. Every AI-generated file also says so
in its header.

**Legend:** **AI-generated** = written by AI, run and reviewed by me · **Mine** = done by me ·
**Guidance** = AI explained or suggested; I did the work · **AI decision** = I asked the AI to
decide and adopted its choice

## Log

| Date | Item | Type | How I verified / what I changed |
|------|------|------|--------------------------------|
| 2026-10-24 | Milestone plan and repo structure | AI-generated | Followed it; adjusted order (tests before README) |
| 2026-10-24 | Choosing Azure over AWS | Mine | Already had an Azure for Students account |
| 2026-10-24 | Azure cost guardrails (budget, Defender check, resource group, CLI setup) | Guidance | Ran each step myself in my subscription |
| 2026-10-24 | Repo skeleton: .gitignore, .env.example, pre-commit config, CI workflow, pyproject, doc templates | AI-generated | Confirmed scans/, data/, .env stay untracked with `git status`; gitleaks hook passed |
| 2026-10-24 | Local environment fixes (Python 3.12 instead of 3.15, Windows long paths, admin window) | Guidance | Diagnosed from my own error output with AI help |
| 2026-10-24 | Scan scoping: one subscription, Entra checks excluded (university tenant) | Guidance | Ran the subscription/tenant checks myself before any scan |
| 2026-10-24 | Baseline triage (docs/baseline-triage.md) | AI-generated | Reviewed each check ID against my real report |
| 2026-10-24 | Public blob deployment, anonymous-access test, remediation commands | Guidance | Ran them; confirmed the anonymous read and the failed list request myself |
| 2026-10-25 | tools/inspect_schema.py, tools/peek_values.py, tools/peek_attacks.py | AI-generated | Ran on my real scans; count matched the HTML report (41) |
| 2026-10-25 | src/cspm/parse_prowler.py | AI-generated | Counts matched all three HTML reports (23 / 41 / 41 findings, FAIL/PASS exact) |
| 2026-10-25 | src/cspm/db.py (SQLite schema, loading, source column) | AI-generated | stats showed stored = file count for every scan; no UNIQUE violations |
| 2026-10-25 | Tier ordering (exposure enablers above detection gaps) | AI decision | I asked the AI to choose; I can explain the reasoning and the counterargument |
| 2026-10-25 | config/check_rules.toml and src/cspm/scoring.py | AI-generated | Tier counts matched a hand calculation from my report (1/3/12/10/9 = 35) |
| 2026-10-25 | src/cspm/diff.py | AI-generated | Matched predicted counts; one wrong prediction exposed a bug in "existence" checks, which was fixed and re-verified |
| 2026-10-25 | Prowler NSG false negative: hypothesis and experiment design | Guidance | I created the rules, ran the scans, and read Prowler's source; results confirmed the hypothesis |
| 2026-10-25 | Decision to keep the Prowler finding in this project (no upstream report) | Mine | |
| 2026-10-25 | src/cspm/nsg_check.py (compensating check) | AI-generated | Flagged my real multi-port rule that Prowler passed |
| 2026-10-25 | Identity misconfiguration and removal (access removed before identity) | Guidance | Ran it; scored P2 as expected; root-scope exclusion held |
| 2026-10-25 | Activity log alerts and alert test | Guidance | Received both alert emails after the test |
| 2026-10-25 | src/cspm/report.py (redacted HTML report) | AI-generated | Searched the output for my subscription ID and email; none found |
| 2026-10-25 | tests/ (32 tests) and updated CI | AI-generated | All pass locally and in GitHub Actions. The AI also re-ran them with the NSG fix removed (2 failed) to show they catch the bug |
| 2026-10-25 | scripts/run_scan.ps1 and infra/teardown.ps1 | AI-generated | Untested when written; both worked on their first real run (teardown + final scan) |
| 2026-10-25 | README.md, docs/findings write-up, GETTING_STARTED.md | AI-generated | Every number comes from my real scans; I filled in the TODO items myself |
| 2026-10-25 | Screenshot selection and redaction | Guidance | I cropped and checked each image for IDs and email |

## How I checked AI output

- **Real data, not assumptions:** field meanings were confirmed against my own scans before the
  parser was written (for example, `status` is "New" for every finding; pass/fail is `status_code`).
- **Predictions before running:** I compared every count to a number worked out in advance. Two
  predictions were wrong, and both exposed real bugs that were fixed.
- **Tests tied to real bugs:** each test covers a problem actually hit during the project.
