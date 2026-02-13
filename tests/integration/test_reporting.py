import pytest
import json
from datetime import datetime, timezone
from src.analyzer.output.writer import JsonWriter, ConsoleWriter
from src.analyzer.models.alert import Alert, Severity

@pytest.fixture
def sample_alerts():
    return [
        Alert(
            timestamp=datetime(2025, 7, 3, 10, 0, 0, tzinfo=timezone.utc),
            rule_name="SQL Injection",
            severity=Severity.HIGH,
            description="Detected UNION SELECT",
            source_ip="192.168.1.100",
            raw_log='GET /search?q=" UNION SELECT...'
        ),
        Alert(
            timestamp=datetime(2025, 7, 3, 10, 0, 5, tzinfo=timezone.utc),
            rule_name="Brute Force",
            severity=Severity.CRITICAL,
            description="3 failed attempts",
            source_ip="10.0.0.50",
            raw_log="Failed password for root"
        )
    ]

def test_json_report_integrity_and_structure(tmp_path, sample_alerts):
    report_file = tmp_path / "report.json"
    writer = JsonWriter()

    with open(report_file, "w", encoding="utf-8") as f:
        writer.write(iter(sample_alerts), destination=f)

    assert report_file.exists()
    
    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert isinstance(data, list)
    assert len(data) == 2
    
    alert1 = data[0]
    assert alert1["rule_name"] == "SQL Injection"
    assert alert1["severity"] == "HIGH"
    assert alert1["source_ip"] == "192.168.1.100"
    
    assert "2025-07-03T10:00:00" in alert1["timestamp"]

def test_json_report_empty(tmp_path):
    report_file = tmp_path / "empty.json"
    writer = JsonWriter()

    with open(report_file, "w", encoding="utf-8") as f:
        writer.write(iter([]), destination=f)

    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    assert data == []

def test_console_writer_to_file(tmp_path, sample_alerts):
    report_file = tmp_path / "report.txt"
    writer = ConsoleWriter()

    with open(report_file, "w", encoding="utf-8") as f:
        writer.write(iter(sample_alerts), destination=f)

    content = report_file.read_text(encoding="utf-8")

    assert "SECURITY ANALYSIS REPORT" in content
    assert "[HIGH] SQL Injection" in content
    assert "IP: 192.168.1.100" in content
    assert "Details: Detected UNION SELECT" in content
    
    assert "[CRITICAL] Brute Force" in content
    assert "Total threats detected: 2" in content

def test_encoding_handling(tmp_path):
    special_char_alert = Alert(
        timestamp=datetime.now(timezone.utc),
        rule_name="Dziwna Reguła",
        severity=Severity.INFO,
        description="Zażółć gęślą jaźń (Unicode test)",
        source_ip="::1",
        raw_log="Zażółć"
    )

    report_file = tmp_path / "unicode.json"
    writer = JsonWriter()

    with open(report_file, "w", encoding="utf-8") as f:
        writer.write(iter([special_char_alert]), destination=f)

    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    assert data[0]["description"] == "Zażółć gęślą jaźń (Unicode test)"