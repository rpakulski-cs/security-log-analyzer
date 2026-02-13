import pytest
import subprocess
import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MAIN_SCRIPT = PROJECT_ROOT / "src" / "analyzer" / "main.py"
TEST_DATA_DIR = PROJECT_ROOT / "tests" / "test_data"
AUTH_LOG = TEST_DATA_DIR / "auth.log"
WEB_LOG = TEST_DATA_DIR / "webserver.log"

def run_cli(args):
    cmd = [sys.executable, str(MAIN_SCRIPT)] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT
    )
    return result

def test_full_security_scan_json_output(tmp_path):
    report_file = tmp_path / "security_report.json"
    
    if not AUTH_LOG.exists() or not WEB_LOG.exists():
        pytest.skip(f"Test data not found in {TEST_DATA_DIR}")

    result = run_cli([
        str(AUTH_LOG),
        str(WEB_LOG),
        "-f", "json",
        "-o", str(report_file)
    ])

    assert result.returncode == 0, f"CLI failed with stderr: {result.stderr}"
    assert report_file.exists()
    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    rule_names = {alert["rule_name"] for alert in data}
    assert "SQL Injection Attempt" in rule_names

def test_default_text_output_stdout_multiple_sources(tmp_path):
    if not WEB_LOG.exists() or not AUTH_LOG.exists():
        pytest.skip("Required files webserver.log i auth.log nare not exists in tests/test_data")

    extra_log = tmp_path / "database_attack.log"
    extra_content = [
        '10.10.10.10 - - [03/Jul/2025:12:00:00 +0000] "GET /shiny-app HTTP/1.1" 200 500',
        '66.66.66.66 - - [03/Jul/2025:12:05:00 +0000] "GET /search?q=item; DROP TABLE users HTTP/1.1" 200 0'
    ]
    extra_log.write_text("\n".join(extra_content), encoding="utf-8")

    result = run_cli([
        str(WEB_LOG),
        str(AUTH_LOG),
        str(extra_log)
    ])

    assert result.returncode == 0, f"CLI failed with stderr: {result.stderr}"
    output = result.stdout
    print("CLI Output:\n%s", output)

    assert "SECURITY ANALYSIS REPORT" in output

    assert "SSH Brute Force" in output or "SSH" in output

    assert "DROP\\s+TABLE" in output

    assert "Total threats detected: 7" in output

def test_resilience_to_garbage_data(tmp_path):
    if not WEB_LOG.exists():
        pytest.skip("webserver.log not found")

    garbage_txt = tmp_path / "garbage.txt"
    garbage_txt.write_text("It is not valid log\nThat one also", encoding="utf-8")
    
    garbage_bin = tmp_path / "binary.dat"
    garbage_bin.write_bytes(b"\x00\xFF\x12\x34\xDE\xAD\xBE\xEF")

    result = run_cli([
        str(WEB_LOG),
        str(garbage_txt),
        str(garbage_bin)
    ])

    assert result.returncode == 0
    assert "SQL Injection Attempt" in result.stdout
    assert f"Unrecognized file type: {garbage_txt.name}" in result.stdout
    assert f"Unrecognized file type: {garbage_bin.name}" in result.stdout

def test_missing_files_error_code():
    result = run_cli(["non_existent_ghost_file.log"])

    assert result.returncode == 1
    assert "No valid input files provided" in result.stderr