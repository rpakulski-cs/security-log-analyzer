import pytest
import io
from pathlib import Path
from src.analyzer.parsers.factory import ParserFactory
from src.analyzer.models.base import WebLogEntry, SSHLogEntry

def test_get_parser_stream_syslog():
    file_path = Path("var/log/auth.log")
    file_content = io.StringIO("Jul  3 10:00:03 server sshd[123]: test")
    
    stream = ParserFactory.get_parser_stream(file_path, file_content)
    
    results = list(stream)
    assert len(results) > 0

def test_get_parser_stream_web():
    file_path = Path("nginx/access.log")
    file_content = io.StringIO('127.0.0.1 - - [01/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 123')
    
    stream = ParserFactory.get_parser_stream(file_path, file_content)
    results = list(stream)
    
    assert len(results) == 1
    assert isinstance(results[0], WebLogEntry)

def test_get_parser_unknown_file():
    file_path = Path("random_file.txt")
    file_content = io.StringIO("content")
    
    with pytest.raises(ValueError) as excinfo:
        ParserFactory.get_parser_stream(file_path, file_content)
    
    assert "Unrecognized file type:" in str(excinfo.value)