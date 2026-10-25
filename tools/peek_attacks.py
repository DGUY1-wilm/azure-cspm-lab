"""Show which MITRE ATT&CK tactics Prowler maps to each check (no IDs printed).

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending
"""
import json
import sys
from collections import Counter
from pathlib import Path

findings = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
tactic_counts = Counter()
unmapped = 0

for f in findings:
    attacks = (f.get("finding_info") or {}).get("attacks") or []
    tactics = sorted({(a.get("tactic") or {}).get("name", "?") for a in attacks})
    tactic_counts.update(tactics)
    if not tactics:
        unmapped += 1
    check = (f.get("metadata") or {}).get("event_code", "?")
    print(f"{check:<62} {f.get('status_code', '?'):<5} {', '.join(tactics) or '(none)'}")

print("\nTactic counts:", dict(tactic_counts.most_common()))
print("Findings with no ATT&CK mapping:", unmapped)