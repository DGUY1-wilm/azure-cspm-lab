"""Print non-identifying values from a Prowler OCSF JSON file to confirm field meanings.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [x] pending
Prints check IDs, statuses, severities, and counts only: no resource or account IDs.
"""
import json
import sys
from collections import Counter
from pathlib import Path


def main():
    findings = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))

    # One line per finding
    for f in findings:
        print(
            f"{f.get('metadata', {}).get('event_code', '?'):<60} "
            f"status_code={f.get('status_code')!s:<5} "
            f"status={f.get('status')!s:<10} "
            f"severity={f.get('severity')}({f.get('severity_id')}) "
            f"resources={len(f.get('resources', []))}"
        )

    # Summary counts, to answer the open questions at a glance
    print("\n--- Summary ---")
    print("status_code:", dict(Counter(f.get("status_code") for f in findings)))
    print("status:     ", dict(Counter(f.get("status") for f in findings)))
    print("severity:   ", dict(Counter(f.get("severity") for f in findings)))
    print("resources per finding:", dict(Counter(len(f.get("resources", [])) for f in findings)))

    # How many findings carry each CIS version (helps choose one)
    cis = Counter()
    no_cis = 0
    for f in findings:
        keys = [k for k in f.get("unmapped", {}).get("compliance", {}) if k.startswith("CIS-")]
        cis.update(keys)
        if not keys:
            no_cis += 1
    print("CIS versions (findings mapped):", dict(sorted(cis.items())))
    print("findings with no CIS mapping:", no_cis)


if __name__ == "__main__":
    main()
