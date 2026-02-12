import pytest
from datetime import datetime, timezone
from src.analyzer.parsers.web import WebLogParser
from src.analyzer.models.base import WebLogEntry, UnparsedLogEntry

@pytest.fixture
def parser():
    return WebLogParser()

VALID_LOG_CASES = [
    (
        '192.168.1.1 - - [03/Jul/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234',
        200, 1234, "GET"
    ),
    (
        '10.0.0.1 - - [03/Jul/2025:10:00:00 +0000] "POST /login HTTP/1.1" 401 -',
        401, 0, "POST"  
    ),
]

@pytest.mark.parametrize("line, expected_status, expected_size, expected_method", VALID_LOG_CASES)
def test_parse_valid_lines(parser, line, expected_status, expected_size, expected_method):
    results = list(parser.parse([line]))
    
    assert len(results) == 1
    entry = results[0]
    
    assert isinstance(entry, WebLogEntry)
    assert entry.status_code == expected_status
    assert entry.response_size_bytes == expected_size
    assert entry.http_method == expected_method
    assert entry.timestamp.year == 2025
    assert str(entry.source_ip) in line

def test_parse_stateful_fallback(parser):
    lines = [
        '192.168.1.1 - - [03/Jul/2025:10:00:00 +0000] "GET /valid HTTP/1.1" 200 100',
        '[MALFORMED ENTRY - system restart]'
    ]
    
    results = list(parser.parse(lines))
    
    assert len(results) == 2
    
    valid_entry = results[0]
    assert isinstance(valid_entry, WebLogEntry)
    assert valid_entry.timestamp == datetime(2025, 7, 3, 10, 0, 0, tzinfo=timezone.utc)
    
    malformed_entry = results[1]
    assert isinstance(malformed_entry, UnparsedLogEntry)
    assert malformed_entry.is_timestamp_estimated is True

    assert malformed_entry.timestamp == valid_entry.timestamp 
    assert "system restart" in malformed_entry.raw_content

def test_parse_invalid_date_format(parser):
    line = '127.0.0.1 - - [BadDate:10:00:00] "GET / HTTP/1.1" 200 123'
    
    results = list(parser.parse([line]))
    
    assert len(results) == 1
    assert isinstance(results[0], UnparsedLogEntry)
    assert "Validation error" in results[0].reason

def test_parse_invalid_ip_validation(parser):
    line = '999.999.999.999 - - [03/Jul/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 0'
    
    results = list(parser.parse([line]))
    
    assert len(results) == 1
    assert isinstance(results[0], UnparsedLogEntry)
    assert "Validation error" in results[0].reason

def test_parse_timestamp_inheritance_web(parser):
    lines = [
        '192.168.1.1 - - [03/Jul/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 100', # Valid log to set timestamp
        'Garbage Data' 
    ]
    
    results = list(parser.parse(lines))
    
    assert len(results) == 2
    assert results[0].timestamp == results[1].timestamp
    assert results[1].is_timestamp_estimated is True