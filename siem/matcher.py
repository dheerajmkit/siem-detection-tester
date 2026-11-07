"""Field matchers for detection selections (Sigma-style).

A selection maps field expressions to expected values:

    Image: 'C:\\Windows\\System32\\cmd.exe'        # exact match
    CommandLine|contains: 'mimikatz'              # substring
    Image|startswith: 'C:\\Windows\\'             # prefix
    Image|endswith: '\\powershell.exe'            # suffix
    CommandLine|re: 'sekurlsa::\\w+'              # regex search

A list of expected values means OR. All field expressions in one
selection must match (AND).
"""
import re

MODIFIERS = ("contains", "startswith", "endswith", "re")


def _match_one(actual, expected, modifier):
    if actual is None:
        return False
    text = actual if isinstance(actual, str) else str(actual)
    want = expected if isinstance(expected, str) else str(expected)
    if not modifier:
        return text == want
    if modifier == "contains":
        return want in text
    if modifier == "startswith":
        return text.startswith(want)
    if modifier == "endswith":
        return text.endswith(want)
    if modifier == "re":
        return re.search(want, text) is not None
    raise ValueError(f"unsupported modifier: {modifier!r}")


def selection_matches(selection, event):
    """True when every field matcher in the selection matches the event."""
    if not isinstance(selection, dict):
        raise ValueError("selection must be a mapping")
    for field_expr, expected in selection.items():
        field, _, modifier = field_expr.partition("|")
        if modifier and modifier not in MODIFIERS:
            raise ValueError(f"unsupported modifier: {modifier!r}")
        values = expected if isinstance(expected, list) else [expected]
        actual = event.get(field)
        if not any(_match_one(actual, value, modifier) for value in values):
            return False
    return True


def all_selections_match(rule, event):
    """Day-1 rule semantics: every selection in detection must match."""
    detection = rule["detection"]
    selections = [v for k, v in detection.items() if k != "condition"]
    return all(selection_matches(sel, event) for sel in selections)
