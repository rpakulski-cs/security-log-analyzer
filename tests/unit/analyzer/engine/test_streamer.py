import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from src.analyzer.engine.streamer import LogStreamer
from src.analyzer.models.base import BaseLogEntry, LogType

def create_entry(ts_hour, name):
    return BaseLogEntry(
        timestamp=datetime(2025, 1, 1, ts_hour, 0, 0, tzinfo=timezone.utc),
        log_type=LogType.GENERIC,
        raw_content=name
    )

@patch("src.analyzer.engine.streamer.ParserFactory")
def test_stream_merged_logs_interleaves_correctly(MockFactory, tmp_path):
    file1 = tmp_path / "file1.log"
    file1.write_text("content1")
    
    file2 = tmp_path / "file2.log"
    file2.write_text("content2")
    
    def side_effect(path, handle):
        if "file1" in str(path):
            yield create_entry(10, "F1_A")
            yield create_entry(12, "F1_B")
        elif "file2" in str(path):
            yield create_entry(11, "F2_A")
            yield create_entry(13, "F2_B")
            
    MockFactory.get_parser_stream.side_effect = side_effect
    
    streamer = LogStreamer()
    result_stream = streamer.stream_merged_logs([file1, file2])
    results = list(result_stream)
    
    assert len(results) == 4
    assert results[0].raw_content == "F1_A" # 10:00
    assert results[1].raw_content == "F2_A" # 11:00
    assert results[2].raw_content == "F1_B" # 12:00
    assert results[3].raw_content == "F2_B" # 13:00

def test_streamer_skips_missing_files():
    streamer = LogStreamer()
    missing_path = Path("non_existent_ghost_file.log")
    
    results = list(streamer.stream_merged_logs([missing_path]))
    assert len(results) == 0