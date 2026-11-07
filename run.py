#!/usr/bin/env python3
"""CLI entry point: validate a detection rule and replay it over events.

Usage:
    python3 run.py <rule.yml> <events.jsonl>

Day-1 semantics: every selection in the rule must match an event for it
to fire (implicit AND). Full condition expressions arrive on day 2.

Exit codes: 2 = usage error or invalid rule, 1 = rule fired on no
events, 0 = rule fired at least once.
"""
import sys

from siem.loader import load_rule, load_events
from siem.validator import validate_rule
from siem.matcher import all_selections_match


def main(argv):
    if len(argv) != 3:
        print("usage: python3 run.py <rule.yml> <events.jsonl>",
              file=sys.stderr)
        return 2
    try:
        rule = load_rule(argv[1])
    except (OSError, ValueError) as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 2
    errors = validate_rule(rule)
    if errors:
        print("rule is invalid:")
        for error in errors:
            print(f"  - {error}")
        return 2
    print(f"rule OK: {rule['title']}")
    try:
        events = load_events(argv[2])
    except (OSError, ValueError) as exc:
        print(f"events error: {exc}", file=sys.stderr)
        return 2
    fired = 0
    for index, event in enumerate(events):
        if all_selections_match(rule, event):
            fired += 1
            print(f"event {index}: FIRED")
        else:
            print(f"event {index}: -")
    print(f"\n{fired}/{len(events)} event(s) fired the rule")
    return 0 if fired else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
