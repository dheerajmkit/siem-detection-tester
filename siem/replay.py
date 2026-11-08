"""Replay engine: run a rule over events and summarize the outcome."""
from .matcher import selection_matches
from .evaluator import parse_condition, evaluate_condition


def replay(rule, events):
    """Evaluate the rule's condition against every event.

    Returns a list of {"index", "fired", "matched"} dicts, where
    "matched" lists the selection names that matched the event.
    """
    detection = rule["detection"]
    ast = parse_condition(detection["condition"])
    selections = {k: v for k, v in detection.items() if k != "condition"}
    results = []
    for index, event in enumerate(events):
        matched = {name: selection_matches(sel, event)
                   for name, sel in selections.items()}
        results.append({
            "index": index,
            "fired": evaluate_condition(ast, matched),
            "matched": sorted(n for n, hit in matched.items() if hit),
        })
    return results


def summarize(results, events):
    """Aggregate replay results; confusion matrix when events have labels.

    Events may carry an optional "label" of "malicious" or "benign".
    """
    total = len(results)
    fired = sum(1 for r in results if r["fired"])
    summary = {"events": total, "fired": fired, "not_fired": total - fired}
    labels = [e.get("label") for e in events]
    if any(label in ("malicious", "benign") for label in labels):
        tp = fp = fn = tn = 0
        for result, event in zip(results, events):
            label = event.get("label")
            if result["fired"] and label == "malicious":
                tp += 1
            elif result["fired"] and label == "benign":
                fp += 1
            elif not result["fired"] and label == "malicious":
                fn += 1
            elif not result["fired"] and label == "benign":
                tn += 1
        summary.update({"true_positives": tp, "false_positives": fp,
                        "false_negatives": fn, "true_negatives": tn})
    return summary
