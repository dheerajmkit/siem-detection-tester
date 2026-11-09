# Usage guide

siem-detection-tester is a personal portfolio project: a Sigma-style
detection rule validator and replay tester in pure Python 3 (standard
library only). It has never been deployed at any employer — it exists
to demonstrate detection-engineering skills.

## Install

Nothing to install beyond Python 3. Clone the repo and run from its root:

```bash
git clone https://github.com/dheerajmkit/siem-detection-tester.git
cd siem-detection-tester
```

## Validate and replay a rule

```bash
python3 run.py <rule.yml> <events.jsonl>
```

Exit codes: `2` = usage error or invalid rule, `1` = the rule fired on
no events, `0` = the rule fired at least once.

## JSON mode

For piping into other tools:

```bash
python3 run.py --json rule.yml events.jsonl > replay.json
```

## Rule format

Sigma-style YAML:

```yaml
title: Suspicious PowerShell download cradle
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'IEX'
  condition: selection
level: high
```

Required fields: `title`, `logsource`, `detection`. `detection` holds
one or more selections plus a `condition` naming them.

## Field matchers

| Expression | Meaning |
| ---------- | ------- |
| `Field: value` | exact match |
| `Field\|contains: value` | substring |
| `Field\|startswith: value` | prefix |
| `Field\|endswith: value` | suffix |
| `Field\|re: pattern` | regex search |

A list of values means OR; multiple fields in one selection mean AND.
Matching is case-sensitive.

## Conditions

Full boolean expressions over selection names:

```
selection
selection_a and not filter
(selection_img or selection_cli) and not filter_admin
```

`and` binds tighter than `or`; `not` binds tightest; parentheses
override. Anything else raises a clear error.

## Events

JSONL — one JSON object per line. An optional `label` of `malicious`
or `benign` enables the true/false-positive summary:

```json
{"Image": "...", "CommandLine": "...", "label": "malicious"}
```

## CI integration

See `examples/ci-check.sh`: validates every rule in a directory and
replays each against its paired events file.

## YAML subset

The built-in parser covers nested mappings, lists of scalars, lists of
mappings, quoted/plain scalars, booleans, nulls, numbers, and `#`
comments. It is not a general YAML implementation — for real Sigma
rules, use PyYAML.

## Tests

```bash
python3 -m pytest tests/ -v
```
