import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from src.analyzer.models.base import WebLogEntry, SSHLogEntry, LogType, UnparsedLogEntry

@pytest.fixture
def ts():
    return datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_log_entry_sorting(ts):
    entry1 = WebLogEntry(
        timestamp=datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
        log_type=LogType.WEB,
        raw_content="",
        source_ip="127.0.0.1",
        http_method="GET",
        request_path="/",
        status_code=200,
        response_size_bytes=100
    )
    entry2 = SSHLogEntry(
        timestamp=datetime(2025, 1, 1, 11, 0, 0, tzinfo=timezone.utc),
        log_type=LogType.SSH,
        raw_content="",
        hostname="server",
        process_name="sshd",
        message="test"
    )
    
    assert entry1 < entry2
    assert not (entry2 < entry1)

def test_web_log_validation_success(ts):
    entry = WebLogEntry(
        timestamp=ts,
        log_type=LogType.WEB,
        raw_content="GET / HTTP/1.1",
        source_ip="192.168.1.1",  
        http_method="GET",
        request_path="/index.html",
        status_code=200,         
        response_size_bytes=1024
    )
    assert str(entry.source_ip) == "192.168.1.1"

def test_web_log_invalid_ip(ts):
    with pytest.raises(ValidationError) as excinfo:
        WebLogEntry(
            timestamp=ts,
            log_type=LogType.WEB,
            raw_content="",
            source_ip="NotAnIPAddress", 
            http_method="GET",
            request_path="/",
            status_code=200,
            response_size_bytes=0
        )
    assert "value is not a valid IPv4 or IPv6 address" in str(excinfo.value)

def test_web_log_invalid_status_code(ts):
    with pytest.raises(ValidationError) as excinfo:
        WebLogEntry(
            timestamp=ts,
            log_type=LogType.WEB,
            raw_content="",
            source_ip="127.0.0.1",
            http_method="GET",
            request_path="/",
            status_code="NotAStatusCode",
            response_size_bytes=0
        )
    assert "Input should be a valid integer" in str(excinfo.value)

def test_ssh_log_optional_fields(ts):
    entry = SSHLogEntry(
        timestamp=ts,
        log_type=LogType.SSH,
        raw_content="sudo log",
        hostname="server",
        process_name="sudo",
        message="command executed",
        source_ip=None 
    )
    assert entry.source_ip is None

def test_models_are_immutable(ts):
    entry = UnparsedLogEntry(
        timestamp=ts,
        log_type=LogType.UNPARSED,
        raw_content="bad log",
        reason="error"
    )
    
    with pytest.raises(ValidationError):
        entry.reason = "new reason"