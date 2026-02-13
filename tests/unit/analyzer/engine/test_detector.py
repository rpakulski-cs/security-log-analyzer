import pytest
from datetime import datetime, timezone
from unittest.mock import Mock
from src.analyzer.engine.detector import ThreatDetector
from src.analyzer.engine.rules import Rule
from src.analyzer.models.alert import Alert, Severity
from src.analyzer.models.base import BaseLogEntry

def test_detector_calls_rules_and_yields_alerts():
    mock_rule = Mock(spec=Rule)
    
    fake_alert = Alert(
        timestamp=datetime.now(timezone.utc), #
        rule_name="TestRule", 
        severity="INFO", 
        description="Test", 
        source_ip="1.1.1.1", 
        raw_log=""
    )
    
    mock_rule.check.side_effect = [fake_alert, None]
    
    detector = ThreatDetector(rules=[mock_rule])
    
    mock_entry = Mock(spec=BaseLogEntry)
    stream = [mock_entry, mock_entry]
    
    results = list(detector.analyze_stream(stream))
    
    assert len(results) == 1
    assert results[0] == fake_alert
    assert mock_rule.check.call_count == 2