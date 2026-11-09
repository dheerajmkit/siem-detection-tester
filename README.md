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
# Detection replay report: Suspicious PowerShell download cradle

event 0: FIRED (matched: selection)
event 1: - (matched: none)
event 2: - (matched: none)

Events: 3, fired: 1, not fired: 2
True positives: 1, false positives: 0, false negatives: 0, true negatives: 2
```

Exit codes: `2` = usage error or invalid rule, `1` = the rule fired on
no events, `0` = the rule fired at least once.

Machine-readable output:

```bash
python3 run.py --json samples/rule-fires.yml samples/events-firing.jsonl
```

## Features

- **Rule validation** — required fields, selection mappings, and
  condition references are checked before anything runs.
- **Sigma-style matchers** — exact, `|contains`, `|startswith`,
  `|endswith`, `|re`; lists are OR, fields in one selection are AND.
- **Full condition evaluator** — `and` / `or` / `not` with parentheses,
  e.g. `(selection_img or selection_cli) and not filter_admin`.
- **Replay engine** — runs the rule over JSONL events and reports per
  event which selections matched.
- **True/false-positive reporting** — events may carry an optional
  `label` of `malicious`/`benign` for a confusion-matrix summary.
- **JSON output** (`--json`) for piping into other tools.

## Try it

```bash
python3 run.py samples/rule-fires.yml samples/events-firing.jsonl
python3 run.py samples/rule-silent.yml samples/events-silent.jsonl  # fires on nothing -> exit 1
python3 run.py --json samples/rule-fires.yml samples/events-firing.jsonl
python3 -m pytest tests/ -v
```

See [docs/USAGE.md](docs/USAGE.md) for the rule format, matcher
reference, and condition syntax, and
[examples/ci-check.sh](examples/ci-check.sh) for a sample CI check.

## Project layout

```
run.py                        # CLI: python3 run.py [--json] <rule.yml> <events.jsonl>
siem/
  __init__.py
  yamlmini.py                 # YAML-subset parser (maps, lists, scalars)
  loader.py                   # rule + JSONL event loading
  validator.py                # rule schema validation
  matcher.py                  # Sigma-style field matchers
  evaluator.py                # condition expression parser + evaluator
  replay.py                   # replay engine + TP/FP summary
  report.py                   # text and JSON report rendering
samples/
  rule-fires.yml              # sample rule that fires (fictional)
  events-firing.jsonl         # 3 sample events, 1 fires (fictional)
  rule-silent.yml             # sample rule that fires on nothing
  events-silent.jsonl         # 3 benign events (fictional)
tests/                        # pytest unit tests
docs/USAGE.md                 # full usage guide
examples/                     # sample CI check script
```
