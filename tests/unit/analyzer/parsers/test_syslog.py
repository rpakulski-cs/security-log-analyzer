import pytest
from datetime import datetime, timezone
from src.analyzer.parsers.syslog import SyslogParser
from src.analyzer.models.base import SSHLogEntry, UnparsedLogEntry

@pytest.fixture
def parser():
    return SyslogParser(year=2024)

SYSLOG_SCENARIOS = [
    # Case 1: Standard Failed Password
    (
        "Jul  3 10:00:03 server sshd[1234]: Failed password for admin from 10.0.0.50 port 52341 ssh2",
        "admin", "10.0.0.50", 52341
    ),
    # Case 2: Invalid User
    (
        "Jul  3 10:00:09 server sshd[1235]: Failed password for invalid user hacker from 203.0.113.5 port 44123 ssh2",
        "hacker", "203.0.113.5", 44123
    ),
]

@pytest.mark.parametrize("line, expected_user, expected_ip, expected_port", SYSLOG_SCENARIOS)
def test_parse_valid_ssh_lines(parser, line, expected_user, expected_ip, expected_port):
    results = list(parser.parse([line]))
    
    assert len(results) == 1
    entry = results[0]
    
    assert isinstance(entry, SSHLogEntry)
    assert entry.user == expected_user
    assert str(entry.source_ip) == expected_ip
    assert entry.port == expected_port
    assert entry.timestamp.year == 2024 

def test_parse_sudo_log(parser):
    line = "Jul  3 10:00:15 server sudo: johndoe : TTY=pts/0 ; COMMAND=/bin/cat"
    
    results = list(parser.parse([line]))
    assert len(results) == 1
    entry = results[0]
    
    assert isinstance(entry, SSHLogEntry)
    assert entry.process_name == "sudo"
    assert entry.source_ip is None
    assert entry.port is None

def test_parse_malformed_syslog(parser):
    line = "This is not a valid syslog entry"
    results = list(parser.parse([line]))
    
    assert isinstance(results[0], UnparsedLogEntry)
    assert results[0].reason == "Regex mismatch"