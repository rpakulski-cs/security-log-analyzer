import pytest
from datetime import datetime, timezone
from src.analyzer.parsers.base import BaseParser
from src.analyzer.models.base import UnparsedLogEntry, LogEntry
from typing import Iterable, Iterator

class ConcreteParser(BaseParser):
    def parse(self, lines: Iterable[str]) -> Iterator[LogEntry]:
        pass

def test_handle_unparsed_no_state():
    parser = ConcreteParser()
    line = "Random garbage content"
    
    result = parser._handle_unparsed(line, 1, "Test Reason")
    
    assert isinstance(result, UnparsedLogEntry)
    assert result.raw_content == line
    assert result.line_number == 1
    assert result.reason == "Test Reason"
    assert result.is_timestamp_estimated is False
    assert result.timestamp.replace(tzinfo=timezone.utc).date() == datetime.now(timezone.utc).date()

def test_handle_unparsed_with_state():
    parser = ConcreteParser()
    
    fixed_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    parser.last_valid_timestamp = fixed_time
    
    line = "[MALFORMED] System panic"
    
    result = parser._handle_unparsed(line, 10, "Regex failure")
    
    assert result.timestamp == fixed_time
    assert result.is_timestamp_estimated is True
    assert result.raw_content == line