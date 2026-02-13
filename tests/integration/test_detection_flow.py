import pytest
from pathlib import Path
from src.analyzer.engine.streamer import LogStreamer
from src.analyzer.engine.detector import ThreatDetector
from src.analyzer.engine.rules import SQLInjectionRule, BruteForceRule, KeywordAlertRule
from src.analyzer.models.alert import Severity

def create_web_log(time_str, path, ip="192.168.1.1"):
    return f'{ip} - - [{time_str}] "GET {path} HTTP/1.1" 200 1024'

def create_ssh_log(time_str, msg, ip="10.0.0.50"):
    return f"{time_str} server sshd[1234]: {msg} from {ip} port 2222 ssh2"

def test_sql_injection_detection(tmp_path):
    log_file = tmp_path / "web_attack.log"
    
    content = [
        # valid logs
        create_web_log("03/Jul/2025:10:00:00 +0000", "/index.html"),
        create_web_log("03/Jul/2025:10:00:01 +0000", "/contact"),
        # attack 1: Union Select
        create_web_log("03/Jul/2025:10:00:02 +0000", "/search?q=' UNION SELECT * FROM users"),
        # valid logs
        create_web_log("03/Jul/2025:10:00:03 +0000", "/about"),
        # attack 2: Etc Passwd
        create_web_log("03/Jul/2025:10:00:04 +0000", "/admin/../../etc/passwd"),
    ]
    
    log_file.write_text("\n".join(content), encoding="utf-8")

    streamer = LogStreamer()
    detector = ThreatDetector(rules=[SQLInjectionRule()])
    
    log_stream = streamer.stream_merged_logs([log_file])
    alerts = list(detector.analyze_stream(log_stream))

    assert len(alerts) == 2
    
    assert alerts[0].rule_name == "SQL Injection Attempt"
    assert "UNION\\s+SELECT" in alerts[0].description
    assert alerts[0].timestamp.minute == 0 and alerts[0].timestamp.second == 2
    
    assert alerts[1].rule_name == "SQL Injection Attempt"
    assert "passwd" in alerts[1].description

def test_ssh_brute_force_detection(tmp_path):
    auth_file = tmp_path / "auth_brute.log"
    
    attacker_ip = "66.66.66.66"
    innocent_ip = "10.0.0.5"

    content = [
        # T=0: attack attemtp 1 (FAIL)
        create_ssh_log("Jul  3 10:00:00", "Failed password for root", ip=attacker_ip),
        
        # T=10: User used wrong passord but from innocent IP (FAIL)
        create_ssh_log("Jul  3 10:00:10", "Failed password for admin", ip=innocent_ip),
        
        # T=20: Attack attempt 2 (FAIL)
        create_ssh_log("Jul  3 10:00:20", "Failed password for root", ip=attacker_ip),
        
        # T=30: Attack attempt 3 (FAIL) - ALERT
        create_ssh_log("Jul  3 10:00:30", "Failed password for root", ip=attacker_ip)
    ]
    
    auth_file.write_text("\n".join(content), encoding="utf-8")

    streamer = LogStreamer()
    
    detector = ThreatDetector(rules=[BruteForceRule(max_attempts=3, window_seconds=60)])
    
    log_stream = streamer.stream_merged_logs([auth_file])
    alerts = list(detector.analyze_stream(log_stream))
    
    assert len(alerts) >= 1
    
    alert = alerts[0]
    assert alert.rule_name == "SSH Brute Force"
    assert alert.source_ip == attacker_ip
    assert alert.severity == Severity.CRITICAL
    assert "Detected 3 failed attempts" in alert.description

def test_unparsed_critical_alert_flow(tmp_path):
    log_file = tmp_path / "web.log"
    
    content = [
        create_web_log("03/Jul/2025:11:12:13 +0000", "/ping"),
        "[MALFORMED ENTRY] Kernel panic: system shutdown initiated immediately",
        "Just some debug info without timestamp"
    ]
    
    log_file.write_text("\n".join(content), encoding="utf-8")

    streamer = LogStreamer()
    detector = ThreatDetector(rules=[KeywordAlertRule()])
    
    log_stream = streamer.stream_merged_logs([log_file])
    alerts = list(detector.analyze_stream(log_stream))

    assert len(alerts) == 1
    
    alert = alerts[0]
    assert alert.severity == Severity.CRITICAL
    assert "system shutdown" in alert.description
    assert "(timestamp approximate)" in alert.description
    assert alert.timestamp.hour == 11 and alert.timestamp.minute == 12