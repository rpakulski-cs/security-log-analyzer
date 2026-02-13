import logging
import pytest
import sys
import json
from unittest.mock import patch

from src.analyzer.main import main

def create_web_content():
    return '192.168.1.1 - - [03/Jul/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024'

def create_ssh_content():
    return 'Jul  3 10:00:01 server sshd[1234]: Failed password for root from 10.0.0.50 port 2222 ssh2'

def test_cli_happy_path_text_output(tmp_path, capsys):
    f1 = tmp_path / "access.log"
    f1.write_text(create_web_content(), encoding="utf-8")
    
    f2 = tmp_path / "auth.log"
    f2.write_text(create_ssh_content(), encoding="utf-8")

    test_args = ["main.py", str(f1), str(f2)]

    with patch.object(sys, "argv", test_args):
        main()

    captured = capsys.readouterr()
    assert "SECURITY ANALYSIS REPORT" in captured.out
    assert "Analysis complete" in captured.out
    assert "Total threats detected: 0" in captured.out

def test_cli_happy_path_json_to_file(tmp_path):
    f1 = tmp_path / "access.log"
    f1.write_text(create_web_content(), encoding="utf-8")
    report_file = tmp_path / "final_report.json"
    test_args = ["main.py", str(f1), "-f", "json", "-o", str(report_file)]

    with patch.object(sys, "argv", test_args):
        main()

    assert report_file.exists()
    
    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    assert isinstance(data, list)
    assert not len(data)

def test_cli_no_arguments(capsys):
    with patch.object(sys, "argv", ["main.py"]):
        with pytest.raises(SystemExit) as e:
            main()
        
        assert e.value.code != 0

    captured = capsys.readouterr()
    assert "the following arguments are required" in captured.err or "usage:" in captured.err

def test_cli_files_not_found(caplog, tmp_path):
    ghost_file = tmp_path / "ghost.log"
    test_args = ["main.py", str(ghost_file)]

    caplog.set_level(logging.ERROR)
    with patch.object(sys, "argv", test_args):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 1

    assert "No valid input files provided" in caplog.text

def test_cli_unknown_format_argument():
    test_args = ["main.py", "dummy.log", "-f", "xml"]
    
    with patch.object(sys, "argv", test_args):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code != 0