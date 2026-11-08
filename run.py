#!/usr/bin/env python3
"""CLI entry point: validate a detection rule and replay it over events.

Usage:
    python3 run.py [--json] <rule.yml> <events.jsonl>

The rule's condition expression (and/or/not with parentheses) is
evaluated per event. Events may carry an optional "label" of
"malicious"/"benign" for true/false-positive reporting.

Exit codes: 2 = usage error or invalid rule, 1 = the rule fired on no
events, 0 = the rule fired at least once.
"""
import sys

from siem.loader import load_rule, load_events
from siem.validator import validate_rule
from siem.replay import replay, summarize
from siem.report import to_text, to_json


def main(argv):
    flags = [a for a in argv[1:] if a.startswith("-")]
    args = [a for a in argv[1:] if not a.startswith("-")]
    if len(args) != 2 or any(f != "--json" for f in flags):
        print("usage: python3 run.py [--json] <rule.yml> <events.jsonl>",
              file=sys.stderr)
        return 2
    try:
        rule = load_rule(args[0])
    except (OSError, ValueError) as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 2
    errors = validate_rule(rule)
    if errors:
        print("rule is invalid:")
        for error in errors:
            print(f"  - {error}")
        return 2
    try:
        events = load_events(args[1])
    except (OSError, ValueError) as exc:
        print(f"events error: {exc}", file=sys.stderr)
        return 2
    try:
        results = replay(rule, events)
    except ValueError as exc:
        print(f"condition error: {exc}", file=sys.stderr)
        return 2
    summary = summarize(results, events)
    if "--json" in flags:
        print(to_json(results, summary, rule["title"]), end="")
    else:
        print(to_text(results, summary, rule["title"]), end="")
    return 0 if summary["fired"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
