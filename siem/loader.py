"""Load Sigma-style detection rules (YAML) and JSONL event files."""
import json

from .yamlmini import parse as parse_yaml


def load_rule(path):
    """Load a detection rule file into a dict."""
    with open(path, encoding="utf-8") as fh:
        data = parse_yaml(fh.read())
    if not isinstance(data, dict):
        raise ValueError(f"{path}: rule must be a YAML mapping")
    return data


def load_events(path):
    """Load a JSONL file; each non-blank line is one event dict."""
    events = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}")
            if not isinstance(event, dict):
                raise ValueError(f"{path}:{lineno}: event must be an object")
            events.append(event)
    return events
