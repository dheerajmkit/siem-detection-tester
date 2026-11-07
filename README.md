# siem-detection-tester

Validates Sigma-style YAML detection rules and replays sample log
events against them to verify they fire. Rules are schema-checked
(title, logsource, detection, condition), events are matched with
Sigma-style field matchers (`contains`, `startswith`, `endswith`,
`re`, exact), and the replay reports which events fired.

This is a **personal portfolio project** exploring detection
engineering and security automation. It is a learning exercise, not a
production tool, and it has never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 run.py samples/rule-fires.yml samples/events-firing.jsonl
```

Output:

```
rule OK: Suspicious PowerShell download cradle
event 0: FIRED
event 1: -
event 2: -

1/3 event(s) fired the rule
```

Exit codes: `2` = usage error or invalid rule, `1` = the rule fired on
no events, `0` = the rule fired at least once.

## Day-1 scope

- Rule loading with a small built-in YAML-subset parser (no PyYAML).
- Schema validation: required fields, selection references in the
  condition.
- Field matchers: exact, `|contains`, `|startswith`, `|endswith`,
  `|re`; lists are OR, fields in one selection are AND.
- Day-1 rule semantics: every selection must match (implicit AND).
  Full `and`/`or`/`not` condition expressions arrive on day 2.

## Project layout

```
run.py                        # CLI: python3 run.py <rule.yml> <events.jsonl>
siem/
  __init__.py
  yamlmini.py                 # YAML-subset parser (maps, lists, scalars)
  loader.py                   # rule + JSONL event loading
  validator.py                # rule schema validation
  matcher.py                  # Sigma-style field matchers
samples/
  rule-fires.yml              # sample rule (fictional)
  events-firing.jsonl         # 3 sample events, 1 fires (fictional)
```

## Notes

- The YAML parser covers the subset detection rules use; it is not a
  general YAML implementation.
- Matching is case-sensitive, like Sigma's default for most backends.
- Sample events use documentation IP ranges (198.51.100.0/24) and
  fictional hostnames.

## Roadmap

- **Day 2:** full condition evaluator (`and`/`or`/`not` with
  parentheses), replay engine with true/false-positive reporting, and
  JSON output.
- **Day 3:** pytest unit tests, usage docs, and a sample CI check.
