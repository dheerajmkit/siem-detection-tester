"""Rule schema validation for Sigma-style detection rules.

Required top-level fields: title, logsource, detection.
``detection`` must be a mapping with a ``condition`` string and at least
one selection. Condition references are checked against the defined
selection names.
"""
import re

REQUIRED_FIELDS = ("title", "logsource", "detection")


def _condition_names(condition):
    names = []
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", condition):
        if token.lower() not in ("and", "or", "not"):
            names.append(token)
    return names


def validate_rule(rule):
    """Return a list of error strings; empty means the rule is valid."""
    if not isinstance(rule, dict):
        return ["rule must be a mapping"]
    errors = []
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"missing required field: {field}")
    if "title" in rule and not isinstance(rule["title"], str):
        errors.append("title must be a string")
    detection = rule.get("detection")
    if isinstance(detection, dict):
        selections = [k for k in detection if k != "condition"]
        if "condition" not in detection:
            errors.append("detection must define a condition")
        if not selections:
            errors.append("detection must define at least one selection")
        condition = detection.get("condition")
        if isinstance(condition, str):
            for name in _condition_names(condition):
                if name not in selections:
                    errors.append(
                        f"condition references unknown selection: {name}")
        for name in selections:
            if not isinstance(detection[name], dict):
                errors.append(f"selection '{name}' must be a mapping")
    elif "detection" in rule:
        errors.append("detection must be a mapping")
    return errors
