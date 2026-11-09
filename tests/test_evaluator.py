"""Unit tests for the SIEM detection tester.

Run with:  python3 -m pytest tests/ -v   (from the repo root)
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from siem.yamlmini import parse as parse_yaml
from siem.loader import load_rule, load_events
from siem.validator import validate_rule
from siem.matcher import selection_matches
from siem.evaluator import parse_condition, evaluate_condition
from siem.replay import replay, summarize

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def _sample(name):
    return os.path.join(SAMPLES, name)


# --- yamlmini ---

def test_yaml_simple_map():
    assert parse_yaml("a: 1\nb: two\n") == {"a": 1, "b": "two"}


def test_yaml_nested_map():
    data = parse_yaml("logsource:\n  product: windows\n  category: process\n")
    assert data == {"logsource": {"product": "windows", "category": "process"}}


def test_yaml_list_of_scalars():
    data = parse_yaml("detection:\n  selection:\n    CommandLine|contains:\n"
                      "      - 'DownloadString'\n      - 'IEX'\n")
    assert data["detection"]["selection"]["CommandLine|contains"] == [
        "DownloadString", "IEX"]


def test_yaml_list_of_maps():
    text = "items:\n  - name: a\n    value: 1\n  - name: b\n    value: 2\n"
    assert parse_yaml(text) == {"items": [{"name": "a", "value": 1},
                                          {"name": "b", "value": 2}]}


def test_yaml_comments_ignored():
    assert parse_yaml("# top\na: 1 # trailing\n") == {"a": 1}


def test_yaml_booleans_and_null():
    data = parse_yaml("a: true\nb: false\nc: null\nd:\n")
    assert data == {"a": True, "b": False, "c": None, "d": None}


def test_yaml_rejects_garbage():
    try:
        parse_yaml("just a scalar: : :\n  bad indent here\n    x")
    except ValueError:
        return
    # either parses or raises; must not hang or return nonsense silently
    raise AssertionError("expected ValueError for malformed yaml")


# --- loader / validator ---

def test_load_sample_rule():
    rule = load_rule(_sample("rule-fires.yml"))
    assert rule["title"] == "Suspicious PowerShell download cradle"
    assert validate_rule(rule) == []


def test_validator_catches_missing_fields():
    errors = validate_rule({"title": "x"})
    assert any("logsource" in e for e in errors)
    assert any("detection" in e for e in errors)


def test_validator_catches_bad_condition_ref():
    rule = {"title": "t", "logsource": {"product": "windows"},
            "detection": {"selection": {"a": "b"}, "condition": "nope"}}
    assert any("nope" in e for e in validate_rule(rule))


def test_load_events():
    events = load_events(_sample("events-firing.jsonl"))
    assert len(events) == 3
    assert events[0]["label"] == "malicious"


# --- matcher ---

def test_exact_match():
    assert selection_matches({"Image": "cmd.exe"}, {"Image": "cmd.exe"})
    assert not selection_matches({"Image": "cmd.exe"}, {"Image": "powershell.exe"})


def test_contains_startswith_endswith():
    event = {"CommandLine": "powershell -enc aGVsbG8="}
    assert selection_matches({"CommandLine|contains": "enc"}, event)
    assert selection_matches({"CommandLine|startswith": "powershell"}, event)
    assert selection_matches({"CommandLine|endswith": "aGVsbG8="}, event)
    assert not selection_matches({"CommandLine|contains": "mimikatz"}, event)


def test_regex_modifier():
    event = {"CommandLine": "sekurlsa::logonpasswords full"}
    assert selection_matches({"CommandLine|re": r"sekurlsa::\w+"}, event)
    assert not selection_matches({"CommandLine|re": r"^mimikatz"}, event)


def test_list_values_are_or():
    event = {"Image": "b.exe"}
    assert selection_matches({"Image": ["a.exe", "b.exe"]}, event)
    assert not selection_matches({"Image": ["a.exe", "c.exe"]}, event)


def test_missing_field_does_not_match():
    assert not selection_matches({"Image": "x"}, {})


def test_bad_modifier_raises():
    try:
        selection_matches({"Image|fuzzy": "x"}, {"Image": "x"})
    except ValueError:
        return
    raise AssertionError("expected ValueError for bad modifier")


# --- evaluator ---

def _eval(condition, **results):
    return evaluate_condition(parse_condition(condition), results)


def test_condition_and_or_not():
    assert _eval("a and b", a=True, b=True)
    assert not _eval("a and b", a=True, b=False)
    assert _eval("a or b", a=False, b=True)
    assert _eval("not a", a=False)
    assert not _eval("not a", a=True)


def test_condition_parens_and_precedence():
    assert _eval("(a or b) and c", a=False, b=True, c=True)
    assert not _eval("(a or b) and c", a=True, b=False, c=False)
    assert _eval("a or b and c", a=False, b=True, c=True)  # and binds tighter
    assert not _eval("not (a or b)", a=True, b=False)


def test_condition_unknown_selection_raises():
    try:
        _eval("nope", a=True)
    except ValueError:
        return
    raise AssertionError("expected ValueError for unknown selection")


def test_condition_bad_syntax_raises():
    for bad in ("a and", "(a or b", "a && b"):
        try:
            parse_condition(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


# --- replay ---

def test_replay_fires_once():
    rule = load_rule(_sample("rule-fires.yml"))
    events = load_events(_sample("events-firing.jsonl"))
    results = replay(rule, events)
    assert [r["fired"] for r in results] == [True, False, False]
    assert results[0]["matched"] == ["selection"]


def test_replay_condition_with_not():
    rule = load_rule(_sample("rule-silent.yml"))
    events = load_events(_sample("events-silent.jsonl"))
    results = replay(rule, events)
    assert not any(r["fired"] for r in results)


def test_summary_confusion_matrix():
    rule = load_rule(_sample("rule-fires.yml"))
    events = load_events(_sample("events-firing.jsonl"))
    summary = summarize(replay(rule, events), events)
    assert summary["fired"] == 1
    assert summary["true_positives"] == 1
    assert summary["false_positives"] == 0
    assert summary["true_negatives"] == 2
    assert summary["false_negatives"] == 0


def test_summary_without_labels():
    rule = load_rule(_sample("rule-fires.yml"))
    events = [{"Image": "x"}]
    summary = summarize(replay(rule, events), events)
    assert "true_positives" not in summary
    assert summary["events"] == 1
