"""siem-detection-tester: validate and replay Sigma-style detection rules."""

from .loader import load_rule, load_events
from .validator import validate_rule
from .matcher import selection_matches, all_selections_match

__all__ = ["load_rule", "load_events", "validate_rule",
           "selection_matches", "all_selections_match"]
__version__ = "0.1.0"
