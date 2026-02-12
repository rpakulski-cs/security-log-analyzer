from typing import Iterator, List

from src.analyzer.models.base import BaseLogEntry
from src.analyzer.models.alert import Alert
from src.analyzer.engine.rules import Rule

class ThreatDetector:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def analyze_stream(self, stream: Iterator[BaseLogEntry]) -> Iterator[Alert]:
        for entry in stream:
            for rule in self.rules:
                alert = rule.check(entry)
                if alert:
                    yield alert