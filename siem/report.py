"""Text and JSON replay report rendering."""
import json


def to_text(results, summary, title):
    """Render replay results and the summary as plain text."""
    lines = [f"# Detection replay report: {title}", ""]
    for result in results:
        status = "FIRED" if result["fired"] else "-"
        matched = ", ".join(result["matched"]) or "none"
        lines.append(f"event {result['index']}: {status} "
                     f"(matched: {matched})")
    lines.append("")
    lines.append(f"Events: {summary['events']}, fired: {summary['fired']}, "
                 f"not fired: {summary['not_fired']}")
    if "true_positives" in summary:
        lines.append(f"True positives: {summary['true_positives']}, "
                     f"false positives: {summary['false_positives']}, "
                     f"false negatives: {summary['false_negatives']}, "
                     f"true negatives: {summary['true_negatives']}")
    return "\n".join(lines) + "\n"


def to_json(results, summary, title):
    """Render replay results and the summary as JSON."""
    return json.dumps({"rule": title, "results": results,
                       "summary": summary}, indent=2) + "\n"
