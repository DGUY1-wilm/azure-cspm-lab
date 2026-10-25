"""Print the field structure of a Prowler OCSF JSON file: names and types only, no values.

[AI-generated] Claude, 2026-10-25. Reviewed by Daniel: [ ] pending
Dev helper for designing the parser. Prints no data, so output is safe to share.
"""
import json
import sys
from pathlib import Path


def walk(obj, path, fields):
    """Record every field path and the types seen there."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            walk(value, f"{path}.{key}" if path else key, fields)
    elif isinstance(obj, list):
        if not obj:
            fields.setdefault(f"{path}[]", set()).add("empty list")
        for item in obj:
            walk(item, f"{path}[]", fields)
    else:
        fields.setdefault(path, set()).add(type(obj).__name__)


def main():
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
    findings = data if isinstance(data, list) else [data]
    print(f"Findings in file: {len(findings)}\n")

    fields = {}
    for finding in findings:
        walk(finding, "", fields)
    for name in sorted(fields):
        print(f"{name}: {', '.join(sorted(fields[name]))}")


if __name__ == "__main__":
    main()