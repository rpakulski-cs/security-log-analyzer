import re
import logging
from typing import Iterator, Iterable
from datetime import datetime
from pydantic import ValidationError

from src.analyzer.parsers.base import BaseParser
from src.analyzer.models.base import WebLogEntry, UnparsedLogEntry

logger = logging.getLogger(__name__)

class WebLogParser(BaseParser):
    LOG_PATTERN = re.compile(
        r'^(\S+)\s+\S+\s+\S+\s+'            
        r'\[([^\]]+)\]\s+'                  
        r'"([A-Z]+)\s+(\S+)\s+[^"]*"\s+'    
        r'(\d{3})\s+'                       
        r'(\d+|-)'                          
    )

    def parse(self, lines: Iterable[str]) -> Iterator[WebLogEntry | UnparsedLogEntry]:
        for line_number, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            match = self.LOG_PATTERN.match(line)
            
            if not match:
                logger.warning(f"Line {line_number}: Regex mismatch.")
                yield self._handle_unparsed(line, line_number, "Regex mismatch")
                continue

            ip_str, raw_ts, method, path, status_str, size_str = match.groups()

            try:
                timestamp = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z")
                size = 0 if size_str == '-' else int(size_str)

                self.last_valid_timestamp = timestamp

                yield WebLogEntry(
                    timestamp=timestamp,
                    source_ip=ip_str, 
                    http_method=method,
                    request_path=path,
                    status_code=int(status_str),
                    response_size_bytes=size,
                    raw_content=line,
                    line_number=line_number
                )

            except (ValueError, ValidationError) as e:
                logger.warning(f"Line {line_number}: Validation error: {e}")
                yield self._handle_unparsed(line, line_number, str(e))