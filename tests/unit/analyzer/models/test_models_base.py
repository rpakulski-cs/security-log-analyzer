import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from src.analyzer.models.base import WebLogEntry, SSHLogEntry, UnparsedLogEntry, LogType

@pytest.fixture
def base_timestamp():
    return datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

@pytest.fixture
def web_entry_factory(base_timestamp):
    def _create(timestamp=base_timestamp, ip="192.168.1.1", status=200):
        return WebLogEntry(
            timestamp=timestamp,
            log_type=LogType.WEB,
            raw_content="GET / HTTP/1.1",
            source_ip=ip,
            http_method="GET",
            request_path="/index.html",
            status_code=status,
            response_size_bytes=1024
        )
    return _create

@pytest.fixture
def ssh_entry_factory(base_timestamp):
    def _create(timestamp=base_timestamp, ip="10.0.0.1"):
        return SSHLogEntry(
            timestamp=timestamp,
            log_type=LogType.SSH,
            raw_content="Failed password",
            hostname="server01",
            process_name="sshd",
            message="Failed password for invalid user",
            source_ip=ip,
            user="root",
            port=22
        )
    return _create

def test_sorting_same_type(web_entry_factory):
    t1 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2025, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    
    entry_early = web_entry_factory(timestamp=t1)
    entry_late = web_entry_factory(timestamp=t2)
    
    assert entry_early < entry_late

def test_sorting_mixed_types(web_entry_factory, ssh_entry_factory):
    t1 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2025, 1, 1, 10, 0, 1, tzinfo=timezone.utc)
    
    web_entry = web_entry_factory(timestamp=t1)
    ssh_entry = ssh_entry_factory(timestamp=t2)
    
    assert web_entry < ssh_entry
    
    web_entry_late = web_entry_factory(timestamp=t2)
    ssh_entry_early = ssh_entry_factory(timestamp=t1)
    
    assert ssh_entry_early < web_entry_late

def test_sorting_with_unparsed(web_entry_factory):
    t1 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2025, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    
    valid_entry = web_entry_factory(timestamp=t1)
    
    unparsed_entry = UnparsedLogEntry(
        timestamp=t2,
        log_type=LogType.UNPARSED,
        raw_content="GARBAGE",
        reason="Error",
        is_timestamp_estimated=True
    )
    
    assert valid_entry < unparsed_entry

def test_comparison_with_other_objects_fails(web_entry_factory):
    entry = web_entry_factory()
    with pytest.raises(TypeError):
        entry < "some string"

def test_web_entry_invalid_ip(web_entry_factory):
    with pytest.raises(ValidationError) as excinfo:
        web_entry_factory(ip="999.999.999.999")
    
    assert "value is not a valid IPv4 or IPv6 address" in str(excinfo.value)

def test_web_entry_invalid_status_code(web_entry_factory):
    with pytest.raises(ValidationError):
        web_entry_factory(status="NotAStatusCode")

def test_ssh_entry_optional_ip(ssh_entry_factory):
    entry = ssh_entry_factory(ip=None)
    assert entry.source_ip is None

def test_immutability(web_entry_factory):
    entry = web_entry_factory()
    
    with pytest.raises(ValidationError) as excinfo:
        entry.status_code = 404
        
    assert "frozen" in str(excinfo.value) or "Instance is frozen" in str(excinfo.value)

def test_timestamp_estimation_flag(base_timestamp):
    valid_entry = WebLogEntry(
        timestamp=base_timestamp,
        log_type=LogType.WEB,
        raw_content="...",
        source_ip="1.1.1.1",
        http_method="GET",
        request_path="/",
        status_code=200,
        response_size_bytes=0
    )
    assert valid_entry.is_timestamp_estimated is False
    
    unparsed = UnparsedLogEntry(
        timestamp=base_timestamp,
        log_type=LogType.UNPARSED,
        raw_content="...",
        reason="...",
        is_timestamp_estimated=True
    )
    assert unparsed.is_timestamp_estimated is True