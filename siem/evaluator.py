"""Condition expression evaluator: AND/OR/NOT with parentheses.

Conditions reference selection names, e.g.::

    selection
    selection_a and not filter
    (selection_1 or selection_2) and not selection_3
"""
import re

_TOKEN_RE = re.compile(r"\(|\)|[A-Za-z_][A-Za-z0-9_]*")
_KEYWORDS = ("and", "or", "not")


def _tokenize(text):
    tokens = []
    for match in _TOKEN_RE.finditer(text):
        word = match.group(0)
        if word in ("(", ")"):
            tokens.append((word, word))
        elif word.lower() in _KEYWORDS:
            tokens.append((word.lower(), word))
        else:
            tokens.append(("name", word))
    leftover = _TOKEN_RE.sub("", text)
    if leftover.strip():
        raise ValueError(
            f"unsupported condition syntax near: {leftover.strip()!r}")
    return tokens


def parse_condition(text):
    """Parse a condition string into an AST tuple."""
    tokens = _tokenize(text)
    if not tokens:
        raise ValueError("condition is empty")
    node, pos = _parse_or(tokens, 0)
    if pos != len(tokens):
        raise ValueError(
            f"unexpected token in condition: {tokens[pos][1]!r}")
    return node


def _parse_or(tokens, pos):
    node, pos = _parse_and(tokens, pos)
    while pos < len(tokens) and tokens[pos][0] == "or":
        rhs, pos = _parse_and(tokens, pos + 1)
        node = ("or", node, rhs)
    return node, pos


def _parse_and(tokens, pos):
    node, pos = _parse_not(tokens, pos)
    while pos < len(tokens) and tokens[pos][0] == "and":
        rhs, pos = _parse_not(tokens, pos + 1)
        node = ("and", node, rhs)
    return node, pos


def _parse_not(tokens, pos):
    if pos < len(tokens) and tokens[pos][0] == "not":
        node, pos = _parse_not(tokens, pos + 1)
        return ("not", node), pos
    return _parse_atom(tokens, pos)


def _parse_atom(tokens, pos):
    if pos >= len(tokens):
        raise ValueError("unexpected end of condition")
    kind, word = tokens[pos]
    if kind == "(":
        node, pos = _parse_or(tokens, pos + 1)
        if pos >= len(tokens) or tokens[pos][0] != ")":
            raise ValueError("missing closing parenthesis in condition")
        return node, pos + 1
    if kind == "name":
        return ("name", word), pos + 1
    raise ValueError(f"unexpected token in condition: {word!r}")


def evaluate_condition(ast, results):
    """Evaluate an AST against {selection_name: bool} results."""
    op = ast[0]
    if op == "name":
        name = ast[1]
        if name not in results:
            raise ValueError(
                f"condition references unknown selection: {name}")
        return bool(results[name])
    if op == "not":
        return not evaluate_condition(ast[1], results)
    if op == "and":
        return (evaluate_condition(ast[1], results)
                and evaluate_condition(ast[2], results))
    if op == "or":
        return (evaluate_condition(ast[1], results)
                or evaluate_condition(ast[2], results))
    raise ValueError(f"unknown condition node: {op!r}")
