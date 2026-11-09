#!/bin/bash
# Sample CI check: validate every rule in rules/ and replay it against
# the events file with the same basename in events/.
#
#   rules/my-rule.yml  +  events/my-rule.jsonl
#
# Fails the build when a rule is invalid or fires on no events.
set -euo pipefail

fail=0
for rule in rules/*.yml; do
  base=$(basename "$rule" .yml)
  events="events/${base}.jsonl"
  if [ ! -f "$events" ]; then
    echo "SKIP $rule (no $events)"
    continue
  fi
  if python3 run.py "$rule" "$events" > /dev/null; then
    echo "PASS $rule"
  else
    echo "FAIL $rule"
    fail=1
  fi
done
exit $fail
