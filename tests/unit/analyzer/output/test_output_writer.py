import pytest
import io
import json
from datetime import datetime, timezone
from src.analyzer.output.writer import ConsoleWriter, JsonWriter
from src.analyzer.models.alert import Alert, Severity

@pytest.fixture
def sample_alerts():
    return [
        Alert(
            timestamp=datetime(2025, 7, 3, 10, 0, 0, tzinfo=timezone.utc),
            rule_name="Test Rule 1",
            severity=Severity.HIGH,
            description="Something happened",
            source_ip="10.0.0.1",
            raw_log="raw log content 1"
        ),
        Alert(
            timestamp=datetime(2025, 7, 3, 10, 0, 5, tzinfo=timezone.utc),
            rule_name="Test Rule 2",
            severity=Severity.CRITICAL,
            description="Critical failure",
            source_ip="192.168.1.1",
            raw_log="raw log content 2"
        )
    ]

def test_json_writer_output_format(sample_alerts):
    output = io.StringIO()
    writer = JsonWriter()
    
    writer.write(sample_alerts, output)
    
    json_content = output.getvalue()
    
    data = json.load(io.StringIO(json_content))
    
    assert len(data) == 2
    assert data[0]["rule_name"] == "Test Rule 1"
    assert data[0]["severity"] == "HIGH"
    assert data[0]["source_ip"] == "10.0.0.1"
    assert "2025-07-03T10:00:00" in data[0]["timestamp"]

def test_json_writer_empty_list():
    output = io.StringIO()
    writer = JsonWriter()
    writer.write([], output)
    
    json_content = output.getvalue()
    data = json.load(io.StringIO(json_content))
    assert data == []

def test_console_writer_contains_keywords(sample_alerts):
    output = io.StringIO()
    writer = ConsoleWriter()
    
    writer.write(sample_alerts, output)
    
    text_content = output.getvalue()
    
    assert "SECURITY ANALYSIS REPORT" in text_content
    assert "[HIGH] Test Rule 1" in text_content
    assert "IP: 10.0.0.1" in text_content
    assert "Critical failure" in text_content
    assert "Total threats detected: 2" in text_content