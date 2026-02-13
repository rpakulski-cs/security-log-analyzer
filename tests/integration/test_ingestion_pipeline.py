import pytest
from pathlib import Path
from datetime import datetime, timezone
from src.analyzer.engine.streamer import LogStreamer
from src.analyzer.models.base import LogType, UnparsedLogEntry

def create_web_log(timestamp_str, path="/index.html"):
    return f'192.168.1.1 - - [{timestamp_str}] "GET {path} HTTP/1.1" 200 1024'

def create_ssh_log(timestamp_str, msg="Failed password for root"):
    return f"{timestamp_str} server sshd[1234]: {msg}"

def test_merge_different_log_formats_chronologically(tmp_path):
    web_file = tmp_path / "access.log"
    auth_file = tmp_path / "auth.log"

    web_content = [
        create_web_log("03/Jul/2025:10:00:00 +0000", "/step1"),
        create_web_log("03/Jul/2025:10:00:10 +0000", "/step3")
    ]
    auth_content = [
        create_ssh_log("Jul  3 10:00:05", "Failed password step2")
    ]

    web_file.write_text("\n".join(web_content), encoding="utf-8")
    auth_file.write_text("\n".join(auth_content), encoding="utf-8")

    streamer = LogStreamer()
    merged_stream = streamer.stream_merged_logs([auth_file, web_file])
    
    results = list(merged_stream)

    assert len(results) == 3
    
    assert results[0].log_type == LogType.WEB
    assert "step1" in results[0].request_path
    
    assert results[1].log_type == LogType.SSH
    assert "step2" in results[1].message
    
    assert results[2].log_type == LogType.WEB
    assert "step3" in results[2].request_path

    assert results[0].timestamp < results[1].timestamp < results[2].timestamp

def test_streamer_skips_unknown_and_missing_files(tmp_path):
    valid_file = tmp_path / "web_access.log"
    valid_file.write_text(create_web_log("03/Jul/2025:12:00:00 +0000"), encoding="utf-8")

    unknown_file = tmp_path / "random_notes.txt"
    unknown_file.write_text("To jest zwykły plik tekstowy, nie log.", encoding="utf-8")

    ghost_file = tmp_path / "ghost.log"

    streamer = LogStreamer()
    
    stream = streamer.stream_merged_logs([valid_file, unknown_file, ghost_file])
    results = list(stream)

    assert len(results) == 1
    assert results[0].log_type == LogType.WEB

def test_stateful_timestamp_persistence(tmp_path):
    log_file = tmp_path / "nginx_error.log"
    
    content = [
        create_web_log("03/Jul/2025:12:00:00 +0000", "/valid"),
        "[MALFORMED ENTRY] System panic 1",
        "[MALFORMED ENTRY] System panic 2",
        create_web_log("03/Jul/2025:12:00:10 +0000", "/valid_again")
    ]
    
    log_file.write_text("\n".join(content), encoding="utf-8")

    streamer = LogStreamer()
    results = list(streamer.stream_merged_logs([log_file]))

    assert len(results) == 4
    assert results[0].log_type == LogType.WEB
    assert results[0].is_timestamp_estimated is False
    ts_base = results[0].timestamp

    assert isinstance(results[1], UnparsedLogEntry)
    assert results[1].is_timestamp_estimated is True
    assert results[1].timestamp == ts_base 
    assert "System panic 1" in results[1].raw_content

    assert isinstance(results[2], UnparsedLogEntry)
    assert results[2].timestamp == ts_base

    assert results[3].log_type == LogType.WEB
    assert results[3].timestamp > ts_base