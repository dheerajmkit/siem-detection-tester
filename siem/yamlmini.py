"""Minimal YAML-subset parser (stdlib only).

Supports what detection-rule samples need: nested mappings, lists of
scalars, lists of mappings ("- key: value" items with continuation
lines), quoted and plain scalars, booleans, nulls, numbers, and '#'
comments. Anything outside the subset raises ValueError.
"""


def _strip_comment(line):
    """Remove a ' #' comment, respecting single/double quotes."""
    in_single = in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1] in " \t":
                return line[:i]
        i += 1
    return line


def _split_key(text):
    """Split 'key: value' on the first colon outside quotes.

    Returns (key, rest) or (text, None) when there is no such colon.
    """
    in_single = in_double = False
    for i, ch in enumerate(text):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            rest = text[i + 1:]
            if rest == "" or rest[0] in " \t":
                return text[:i], rest.strip()
    return text, None


def _unquote(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _parse_scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    low = text.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~", ""):
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def parse(text):
    """Parse a YAML-subset document into Python objects."""
    lines = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        content = _strip_comment(raw).rstrip()
        if not content.strip():
            continue
        indent = len(content) - len(content.lstrip(" "))
        lines.append((indent, content.strip(), lineno))
    if not lines:
        return {}
    result, next_i = _parse_block(lines, 0, lines[0][0])
    if next_i != len(lines):
        raise ValueError(f"line {lines[next_i][2]}: unexpected content")
    return result


def _parse_block(lines, i, indent):
    content = lines[i][1]
    if content == "-" or content.startswith("- "):
        return _parse_list(lines, i, indent)
    return _parse_map(lines, i, indent)


def _parse_map(lines, i, indent):
    result = {}
    n = len(lines)
    while i < n:
        ind, content, lineno = lines[i]
        if ind != indent:
            break
        if content == "-" or content.startswith("- "):
            break
        key, rest = _split_key(content)
        if rest is None:
            raise ValueError(f"line {lineno}: expected 'key: value'")
        key = _unquote(key)
        if rest == "":
            if i + 1 < n and lines[i + 1][0] > indent:
                value, i = _parse_block(lines, i + 1, lines[i + 1][0])
                result[key] = value
            else:
                result[key] = None
                i += 1
        else:
            result[key] = _parse_scalar(rest)
            i += 1
    return result, i


def _parse_list(lines, i, indent):
    items = []
    n = len(lines)
    while i < n:
        ind, content, lineno = lines[i]
        if ind != indent:
            break
        if not (content == "-" or content.startswith("- ")):
            break
        item_text = content[1:].strip()
        if item_text == "":
            if i + 1 < n and lines[i + 1][0] > indent:
                value, i = _parse_block(lines, i + 1, lines[i + 1][0])
                items.append(value)
            else:
                items.append(None)
                i += 1
            continue
        key, rest = _split_key(item_text)
        if (rest is not None and key.strip()
                and not key.strip().startswith(("\"", "'"))):
            # "- key: value" inline map, with possible continuation lines
            sub = [(indent + 2, item_text, lineno)]
            j = i + 1
            while j < n and lines[j][0] > indent:
                sub.append(lines[j])
                j += 1
            value, _ = _parse_map(sub, 0, indent + 2)
            items.append(value)
            i = j
        else:
            items.append(_parse_scalar(item_text))
            i += 1
    return items, i
