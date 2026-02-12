import pytest
from datetime import datetime, timedelta, timezone
from src.analyzer.engine.rules import SQLInjectionRule, BruteForceRule, KeywordAlertRule
from src.analyzer.models.base import WebLogEntry, SSHLogEntry, UnparsedLogEntry, LogType

@pytest.fixture
def base_time():
    return datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

@pytest.fixture
def web_entry(base_time):
    def _create(path="/index.html"):
        return WebLogEntry(
            timestamp=base_time,
            log_type=LogType.WEB,
            raw_content=f"GET {path}",
            source_ip="192.168.1.1",
            http_method="GET",
            request_path=path,
            status_code=200,
            response_size_bytes=100
        )
    return _create

@pytest.fixture
def ssh_entry(base_time):
    def _create(ip="10.0.0.1", message="Failed password for root", offset_seconds=0):
        return SSHLogEntry(
            timestamp=base_time + timedelta(seconds=offset_seconds),
            log_type=LogType.SSH,
            raw_content=f"SSH log from {ip}",
            hostname="server",
            process_name="sshd",
            message=message,
            source_ip=ip,
            user="root",
            port=22
        )
    return _create

def test_sql_rule_matches_pattern(web_entry):
    rule = SQLInjectionRule()
    
    entry = web_entry(path="/search?q=' UNION SELECT * FROM users")
    alert = rule.check(entry)
    assert alert is not None
    assert "UNION\\s+SELECT" in alert.description
    assert alert.severity == "HIGH"

    entry = web_entry(path="/login?user=admin' OR 1=1--")
    alert = rule.check(entry)
    assert alert is not None

def test_sql_rule_ignores_safe_traffic(web_entry):
    rule = SQLInjectionRule()
    entry = web_entry(path="/products/item?id=123")
    assert rule.check(entry) is None

def test_sql_rule_ignores_non_web_logs(ssh_entry):
    rule = SQLInjectionRule()
    entry = ssh_entry()
    assert rule.check(entry) is None


def test_bruteforce_triggers_alert(ssh_entry):
    rule = BruteForceRule(max_attempts=3, window_seconds=60)
    
    assert rule.check(ssh_entry(offset_seconds=0)) is None
    assert rule.check(ssh_entry(offset_seconds=10)) is None
    alert = rule.check(ssh_entry(offset_seconds=20))
    
    assert alert is not None
    assert alert.rule_name == "SSH Brute Force"
    assert "Detected 3 failed attempts" in alert.description
    assert alert.source_ip == "10.0.0.1"

def test_bruteforce_sliding_window(ssh_entry):
    rule = BruteForceRule(max_attempts=3, window_seconds=60)
    
    rule.check(ssh_entry(offset_seconds=0))
    
    rule.check(ssh_entry(offset_seconds=30))
    
    alert = rule.check(ssh_entry(offset_seconds=70))
    assert alert is None

    alert = rule.check(ssh_entry(offset_seconds=80))
    assert alert is not None
    assert "Detected 3 failed attempts" in alert.description

def test_bruteforce_isolates_ips(ssh_entry):
    rule = BruteForceRule(max_attempts=2, window_seconds=60)
    
    rule.check(ssh_entry(ip="10.0.0.1"))
    rule.check(ssh_entry(ip="192.168.0.1")) # Inne IP
    
    alert = rule.check(ssh_entry(ip="10.0.0.1"))
    assert alert is not None
    assert alert.source_ip == "10.0.0.1"

def test_keyword_rule_detects_restart(base_time):
    rule = KeywordAlertRule()
    entry = UnparsedLogEntry(
        timestamp=base_time,
        log_type=LogType.UNPARSED,
        raw_content="[MALFORMED] system restart initiated",
        reason="Regex mismatch",
        line_number=1,
        is_timestamp_estimated=True
    )
    
    alert = rule.check(entry)
    assert alert is not None
    assert alert.severity == "CRITICAL"
    assert "timestamp approximate" in alert.description
    assert "system restart" in alert.description

def test_keyword_rule_ignores_innocent_unparsed(base_time):
    rule = KeywordAlertRule()
    entry = UnparsedLogEntry(
        timestamp=base_time,
        log_type=LogType.UNPARSED,
        raw_content="Just some random garbage log",
        reason="Regex mismatch",
        line_number=1
    )
    assert rule.check(entry) is None