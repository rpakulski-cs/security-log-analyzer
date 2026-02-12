import re
import logging
from typing import Iterator, Iterable, Optional
from datetime import datetime, timezone
from pydantic import ValidationError

from src.analyzer.models.base import WebLogEntry, UnparsedLogEntry, LogType

logger = logging.getLogger(__name__)

class WebLogParser:
    
    LOG_PATTERN = re.compile(
        r'^(\S+)\s+\S+\s+\S+\s+'            
        r'\[([^\]]+)\]\s+'                  
        r'"([A-Z]+)\s+(\S+)\s+[^"]*"\s+'    
        r'(\d{3})\s+'                       
        r'(\d+|-)'                          
    )

    def __init__(self):
        self.last_valid_timestamp: Optional[datetime] = None

    def parse(self, lines: Iterable[str]) -> Iterator[WebLogEntry | UnparsedLogEntry]:
        for line_number, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            match = self.LOG_PATTERN.match(line)
            
            if not match:
                logger.warning(f"Line {line_number}: Regex mismatch. Content: '{line[:50]}...'")
                yield self._handle_unparsed(line, line_number, "Regex mismatch")
                continue

            ip_str, raw_ts, method, path, status_str, size_str = match.groups()

            try:
                timestamp = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z")
                size = 0 if size_str == '-' else int(size_str)

                # Update state
                self.last_valid_timestamp = timestamp

                entry = WebLogEntry(
                    timestamp=timestamp,
                    source_ip=ip_str, 
                    http_method=method,
                    request_path=path,
                    status_code=int(status_str),
                    response_size_bytes=size,
                    raw_content=line,
                    line_number=line_number
                )
                yield entry

            except (ValueError, ValidationError) as e:
                logger.warning(f"Line {line_number}: Validation error: {e}. Content: '{line[:50]}...'")
                yield self._handle_unparsed(line, line_number, str(e))

    def _handle_unparsed(self, line: str, line_num: int, reason: str) -> UnparsedLogEntry:
        return UnparsedLogEntry(
            timestamp=self.last_valid_timestamp or datetime.now(timezone.utc),
            is_timestamp_estimated=True if self.last_valid_timestamp else False,
            raw_content=line,
            source_ip="test",
            line_number=line_num,
            reason=reason
        )