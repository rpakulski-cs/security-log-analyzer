import re
import logging
from typing import Iterator, Iterable, Optional
from datetime import datetime, timezone
from pydantic import ValidationError

from src.analyzer.parsers.base import BaseParser
from src.analyzer.models.base import SSHLogEntry, UnparsedLogEntry

logger = logging.getLogger(__name__)

class SyslogParser(BaseParser):
    SYSLOG_PATTERN = re.compile(
        r'^([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+'
        r'(\S+)\s+'
        r'([a-zA-Z0-9_\-\.]+)(?:\[(\d+)\])?:\s+'
        r'(.*)$'
    )

    IP_PATTERN = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})')
    PORT_PATTERN = re.compile(r'port\s+(\d+)')
    USER_PATTERN = re.compile(r'(?:user|for)\s+(\S+)')

    def __init__(self, year: int = datetime.now().year):
        super().__init__()
        self.default_year = year

    def parse(self, lines: Iterable[str]) -> Iterator[SSHLogEntry | UnparsedLogEntry]:
        for line_number, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            match = self.SYSLOG_PATTERN.match(line)
            
            if not match:
                logger.warning(f"Line {line_number}: Regex mismatch (Syslog).")
                yield self._handle_unparsed(line, line_number, "Regex mismatch")
                continue

            raw_ts, hostname, process, pid_str, message = match.groups()

            try:
                timestamp = self._parse_timestamp(raw_ts)
                self.last_valid_timestamp = timestamp
                
                ip_address = self._extract_ip(message)
                port = self._extract_port(message)
                user = self._extract_user(message)

                yield SSHLogEntry(
                    timestamp=timestamp,
                    raw_content=line,
                    hostname=hostname,
                    process_name=process,
                    pid=int(pid_str) if pid_str else None,
                    message=message,
                    source_ip=ip_address, 
                    user=user,
                    port=port,
                    line_number=line_number
                )

            except (ValueError, ValidationError) as e:
                logger.warning(f"Line {line_number}: Validation error: {e}")
                yield self._handle_unparsed(line, line_number, f"Validation error: {e}")

    def _parse_timestamp(self, raw_ts: str) -> datetime:
        dt_str = f"{raw_ts} {self.default_year}"
        dt = datetime.strptime(dt_str, "%b %d %H:%M:%S %Y")
        return dt.replace(tzinfo=timezone.utc)

    def _extract_ip(self, message: str) -> Optional[str]:
        match = self.IP_PATTERN.search(message)
        return match.group(1) if match else None

    def _extract_port(self, message: str) -> Optional[int]:
        match = self.PORT_PATTERN.search(message)
        return int(match.group(1)) if match else None

    def _extract_user(self, message: str) -> Optional[str]:
        if "invalid user" in message:
            parts = message.split("invalid user ")
            if len(parts) > 1:
                return parts[1].split()[0]
        
        match = self.USER_PATTERN.search(message)
        if match and match.group(1) != "invalid":
            return match.group(1)
        return None