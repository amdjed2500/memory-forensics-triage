"""Detection rule engine (Sigma-compatible YAML)."""
import os
import yaml
from typing import List, Dict, Any


class RuleEngine:
    def __init__(self, rules_dir=None):
        self.rules = []
        if rules_dir and os.path.isdir(rules_dir):
            self.load_rules(rules_dir)

    def load_rules(self, rules_dir):
        for root, _, files in os.walk(rules_dir):
            for f in files:
                if f.endswith((".yml", ".yaml")):
                    path = os.path.join(root, f)
                    with open(path) as fh:
                        doc = yaml.safe_load(fh)
                        if doc:
                            self.rules.append(doc)

    def evaluate(self, data: Dict[str, Any]) -> List[Dict]:
        """Evaluate all rules against a data dict. Returns list of findings."""
        findings = []
        for rule in self.rules:
            detection = rule.get("detection", {})
            selection = detection.get("selection", {})
            condition = detection.get("condition", "selection")
            if self._match(selection, data):
                findings.append({
                    "id": rule.get("id", "unknown"),
                    "title": rule.get("title", "Unnamed rule"),
                    "level": rule.get("level", "medium"),
                    "tags": rule.get("tags", []),
                    "description": rule.get("description", ""),
                })
        return findings

    def _match(self, selection, data):
        """Check if selection criteria match data."""
        if not selection:
            return False
        for key, expected in selection.items():
            actual = data.get(key)
            if isinstance(expected, str) and expected.startswith(">"):
                try:
                    if not (actual is not None and actual > int(expected[1:])):
                        return False
                except (ValueError, TypeError):
                    return False
            elif isinstance(expected, str) and expected.startswith("<"):
                try:
                    if not (actual is not None and actual < int(expected[1:])):
                        return False
                except (ValueError, TypeError):
                    return False
            else:
                if actual != expected:
                    return False
        return True