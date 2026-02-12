import re
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import timedelta
from typing import Optional

from src.analyzer.models.base import BaseLogEntry, WebLogEntry, SSHLogEntry, UnparsedLogEntry
from src.analyzer.models.alert import Alert, Severity

class Rule(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def check(self, entry: BaseLogEntry) -> Optional[Alert]:
        pass

class SQLInjectionRule(Rule):
    name = "SQL Injection Attempt"
    
    PATTERNS = [
        re.compile(r"UNION\s+SELECT", re.IGNORECASE),
        re.compile(r"OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE),
        re.compile(r"(\'|%27)\s*--", re.IGNORECASE), 
        re.compile(r";\s*DROP\s+TABLE", re.IGNORECASE), 
        re.compile(r"\.\./\.\./etc/passwd"), 
    ]

    def check(self, entry: BaseLogEntry) -> Optional[Alert]:
        if not isinstance(entry, WebLogEntry):
            return None

        if entry.request_path:
            for pattern in self.PATTERNS:
                if pattern.search(entry.request_path):
                    return Alert(
                        timestamp=entry.timestamp,
                        rule_name=self.name,
                        severity=Severity.HIGH,
                        description=f"Pattern match: {pattern.pattern}",
                        source_ip=str(entry.source_ip),
                        raw_log=entry.raw_content
                    )
        return None

class BruteForceRule(Rule):
    name = "SSH Brute Force"

    def __init__(self, max_attempts: int = 3, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window = timedelta(seconds=window_seconds)
        
        self.attempts: dict[str, deque] = defaultdict(deque)

    def check(self, entry: BaseLogEntry) -> Optional[Alert]:
        if not isinstance(entry, SSHLogEntry):
            return None

        if "Failed password" not in entry.message and "invalid user" not in entry.message:
            return None

        ip = str(entry.source_ip)
        if not ip: 
            return None

        self.attempts[ip].append(entry.timestamp)

        cutoff_time = entry.timestamp - self.window
        
        while self.attempts[ip] and self.attempts[ip][0] < cutoff_time:
            self.attempts[ip].popleft()

        if len(self.attempts[ip]) >= self.max_attempts:
            return Alert(
                timestamp=entry.timestamp,
                rule_name=self.name,
                severity=Severity.CRITICAL,
                description=f"Detected {len(self.attempts[ip])} failed attempts in {self.window.seconds}s",
                source_ip=ip,
                raw_log=entry.raw_content
            )
            
        return None

class KeywordAlertRule(Rule):
    name = "Critical System Event"
    KEYWORDS = ["restart", "shutdown", "panic", "error", "malformed"]

    def check(self, entry: BaseLogEntry) -> Optional[Alert]:
        if not isinstance(entry, UnparsedLogEntry):
            return None

        content_lower = entry.raw_content.lower()
        if any(keyword in content_lower for keyword in self.KEYWORDS):
            description = "Critical system event detected"
            if entry.is_timestamp_estimated:
                description += " (timestamp approximate)"

            return Alert(
                timestamp=entry.timestamp,
                rule_name=self.name,
                severity=Severity.CRITICAL,
                description=f"{description}: '{entry.raw_content}'",
                source_ip="Local System",
                raw_log=entry.raw_content
            )
        return None