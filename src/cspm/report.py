"""Generate a redacted HTML report from the scan database.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending

Every piece of text passes through redact() before it is written, because Prowler
embeds subscription IDs inside status_detail. Output contains no GUIDs or emails.

Usage (from the repo root, with PYTHONPATH=src):
    python -m cspm.report                      # latest scan, all history
    python -m cspm.report --label after-alerts --out reports/report.html
"""
from __future__ import annotations

import argparse
import html
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from cspm.db import DEFAULT_DB, connect
from cspm.diff import compare
from cspm.scoring import DEFAULT_RULES, load_rules, score_scan

GUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
TIERS = ["P1", "P2", "P3", "P4", "unclassified", "excluded"]
TIER_LABELS = {
    "P1": "P1 · Direct exposure", "P2": "P2 · Exposure enabler", "P3": "P3 · Detection gap",
    "P4": "P4 · Hardening", "unclassified": "Unclassified", "excluded": "Excluded (triaged)",
}


def redact(text: str | None) -> str:
    """Replace GUIDs and email addresses, then HTML-escape."""
    text = GUID.sub("‹id›", text or "")
    text = EMAIL.sub("‹email›", text)
    return html.escape(text)


def _scans(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT s.label, s.scanned_at, SUM(f.status = 'FAIL') AS fails, "
        "SUM(f.status = 'PASS') AS passes FROM scans s "
        "JOIN findings f ON f.scan_id = s.scan_id GROUP BY s.scan_id ORDER BY s.scanned_at"
    ).fetchall()
    return [dict(r) for r in rows]


def _tier_chart(history: list[dict]) -> str:
    """Inline SVG: one stacked bar per scan, segments by tier (excluded left out)."""
    shown = ["P1", "P2", "P3", "P4", "unclassified"]
    max_total = max((sum(h["tiers"].get(t, 0) for t in shown) for h in history), default=1) or 1
    bar_h, gap, label_w, chart_w = 22, 10, 170, 520
    height = len(history) * (bar_h + gap) + 30
    parts = [f'<svg viewBox="0 0 {label_w + chart_w + 60} {height}" role="img" '
             f'aria-label="Open findings by tier per scan" class="chart">']
    for i, h in enumerate(history):
        y = i * (bar_h + gap)
        parts.append(f'<text x="{label_w - 8}" y="{y + 16}" text-anchor="end" class="axis">{redact(h["label"])}</text>')
        x = label_w
        for t in shown:
            n = h["tiers"].get(t, 0)
            if n:
                w = n / max_total * chart_w
                parts.append(f'<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="{bar_h}" class="seg-{t}">'
                             f'<title>{t}: {n}</title></rect>')
                x += w
        total = sum(h["tiers"].get(t, 0) for t in shown)
        parts.append(f'<text x="{x + 6:.1f}" y="{y + 16}" class="axis">{total}</text>')
    legend_y = len(history) * (bar_h + gap) + 14
    lx = label_w
    for t in shown:
        parts.append(f'<rect x="{lx}" y="{legend_y - 10}" width="12" height="12" class="seg-{t}"/>'
                     f'<text x="{lx + 16}" y="{legend_y}" class="axis">{t}</text>')
        lx += 95
    parts.append("</svg>")
    return "".join(parts)


def build_report(conn, rules: dict, label: str | None = None) -> str:
    scans = _scans(conn)
    if not scans:
        raise SystemExit("No scans in the database; load some first")
    label = label or scans[-1]["label"]

    history = []
    for s in scans:
        tiers = Counter(f.tier for f in score_scan(conn, s["label"], rules))
        history.append({**s, "tiers": tiers})

    current = score_scan(conn, label, rules)
    counts = Counter(f.tier for f in current)
    details = {r["id"]: dict(r) for r in conn.execute(
        "SELECT f.id, f.status_detail, f.remediation, f.source FROM findings f "
        "JOIN scans s ON s.scan_id = f.scan_id WHERE s.label = ?", (label,))}

    # Changes between each consecutive pair of scans (persisting left out)
    timeline = []
    for before, after in zip(scans, scans[1:]):
        changes = [c for c in compare(conn, before["label"], after["label"], rules)
                   if c.change != "persisting"]
        timeline.append((before["label"], after["label"], changes))

    cards = "".join(
        f'<div class="card tier-{t}"><div class="num">{counts.get(t, 0)}</div>'
        f'<div class="lbl">{TIER_LABELS[t]}</div></div>' for t in TIERS)

    rows = []
    for f in current:
        d = details[f.finding_id]
        src = '<span class="badge">custom</span> ' if d["source"] == "custom" else ""
        rows.append(
            f'<tr class="row-{f.tier}"><td><span class="pill tier-{f.tier}">{f.tier}</span></td>'
            f"<td>{redact(f.severity)}</td><td>{src}<code>{redact(f.check_id)}</code><br>"
            f'<span class="muted">{redact(d["status_detail"])}</span></td>'
            f"<td>{redact(f.resource_name)}</td><td>{redact(f.tactic)}</td>"
            f"<td>{redact(f.reason)}</td></tr>")

    tl = []
    for before, after, changes in timeline:
        items = "".join(
            f'<li><span class="chg chg-{c.change}">{c.change}</span> '
            f'<span class="pill tier-{c.tier}">{c.tier}</span> <code>{redact(c.check_id)}</code></li>'
            for c in changes) or '<li class="muted">No changes in failing findings</li>'
        tl.append(f"<h3>{redact(before)} → {redact(after)}</h3><ul class=\"changes\">{items}</ul>")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return TEMPLATE.format(
        label=redact(label), generated=generated, scan_count=len(scans), cards=cards,
        chart=_tier_chart(history), rows="".join(rows), timeline="".join(tl),
        fails=sum(1 for f in current), )


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Azure CSPM Lab — Posture Report</title>
<style>
:root {{ --bg:#f7f7f5; --surface:#fff; --text:#1d1d1b; --muted:#6b6b66; --line:#e3e2dd;
  --p1:#c62828; --p2:#e67e22; --p3:#c9a227; --p4:#3d7ab8; --unc:#8e44ad; --exc:#9a9a94; }}
@media (prefers-color-scheme: dark) {{ :root {{ color-scheme: dark; --bg:#161615; --surface:#1f1f1d;
  --text:#ecebe6; --muted:#a3a29b; --line:#33322f; --p3:#d9b43a; --p4:#5b9bd5; }} }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
main {{ max-width:1100px; margin:0 auto; padding:32px 20px 60px; }}
h1 {{ margin:0 0 4px; font-size:26px; }} h2 {{ margin:36px 0 12px; font-size:19px; }}
h3 {{ margin:18px 0 6px; font-size:15px; }}
.muted {{ color:var(--muted); font-size:13px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-top:20px; }}
.card {{ background:var(--surface); border:1px solid var(--line); border-left:5px solid; border-radius:8px; padding:12px 14px; }}
.card .num {{ font-size:28px; font-weight:650; }} .card .lbl {{ font-size:13px; color:var(--muted); }}
.tier-P1 {{ border-color:var(--p1); }} .tier-P2 {{ border-color:var(--p2); }} .tier-P3 {{ border-color:var(--p3); }}
.tier-P4 {{ border-color:var(--p4); }} .tier-unclassified {{ border-color:var(--unc); }} .tier-excluded {{ border-color:var(--exc); }}
.pill {{ display:inline-block; padding:1px 8px; border-radius:10px; font-size:12px; font-weight:600; color:#fff; }}
.pill.tier-P1 {{ background:var(--p1); }} .pill.tier-P2 {{ background:var(--p2); }} .pill.tier-P3 {{ background:var(--p3); }}
.pill.tier-P4 {{ background:var(--p4); }} .pill.tier-unclassified {{ background:var(--unc); }} .pill.tier-excluded {{ background:var(--exc); }}
.panel {{ background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:16px; overflow-x:auto; }}
.chart {{ width:100%; max-width:760px; height:auto; }} .axis {{ font-size:12px; fill:var(--text); }}
.seg-P1 {{ fill:var(--p1); }} .seg-P2 {{ fill:var(--p2); }} .seg-P3 {{ fill:var(--p3); }}
.seg-P4 {{ fill:var(--p4); }} .seg-unclassified {{ fill:var(--unc); }}
table {{ width:100%; border-collapse:collapse; font-size:13.5px; }}
th,td {{ text-align:left; vertical-align:top; padding:8px; border-bottom:1px solid var(--line); }}
th {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }}
tr.row-excluded {{ opacity:.6; }}
code {{ font-family:ui-monospace,Consolas,monospace; font-size:12.5px; }}
.badge {{ font-size:11px; border:1px solid var(--p2); color:var(--p2); border-radius:4px; padding:0 4px; }}
.changes {{ list-style:none; padding:0; margin:0; }} .changes li {{ padding:3px 0; }}
.chg {{ display:inline-block; width:56px; font-size:12px; font-weight:600; }}
.chg-new {{ color:var(--p1); }} .chg-fixed {{ color:#2e8b57; }} .chg-gone {{ color:var(--muted); }}
</style></head>
<body><main>
<h1>Azure CSPM Lab — Posture Report</h1>
<div class="muted">Current scan: <b>{label}</b> · {scan_count} scans in history · generated {generated} ·
identifiers redacted</div>

<div class="cards">{cards}</div>

<h2>Open findings by tier, across every scan</h2>
<div class="panel">{chart}</div>
<p class="muted">Tiers come from my exposure-based rules (config/check_rules.toml), not Prowler's
severity. Excluded findings are triage decisions and are not charted.</p>

<h2>What changed between scans</h2>
<div class="panel">{timeline}</div>

<h2>Prioritized findings — {label} ({fails} failing)</h2>
<div class="panel"><table>
<thead><tr><th>Tier</th><th>Prowler severity</th><th>Check / detail</th><th>Resource</th>
<th>My ATT&amp;CK tactic</th><th>Why this tier</th></tr></thead>
<tbody>{rows}</tbody></table></div>
</main></body></html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Write the redacted HTML report.")
    parser.add_argument("--label", help="scan to detail (default: most recent)")
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--rules", default=DEFAULT_RULES)
    parser.add_argument("--out", default=str(Path("reports") / "report.html"))
    args = parser.parse_args()

    conn = connect(args.db)
    try:
        page = build_report(conn, load_rules(args.rules), args.label)
    finally:
        conn.close()

    leaks = GUID.findall(page) + EMAIL.findall(page)
    if leaks:
        raise SystemExit(f"Refusing to write report: {len(leaks)} identifier(s) survived redaction")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8")
    print(f"Report written to {out}")


if __name__ == "__main__":
    main()
