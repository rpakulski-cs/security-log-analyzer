import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from src.analyzer.models.base import LogEntry, UnparsedLogEntry

logger = logging.getLogger(__name__)

class BaseParser(ABC):
    def __init__(self):
        self.last_valid_timestamp: Optional[datetime] = None

    @abstractmethod
    def parse(self, lines: Iterable[str]) -> Iterator[LogEntry]:
        pass

    def _handle_unparsed(self, line: str, line_num: int, reason: str) -> UnparsedLogEntry:
        return UnparsedLogEntry(
            timestamp=self.last_valid_timestamp or datetime.now(timezone.utc),
            is_timestamp_estimated=True if self.last_valid_timestamp else False,
            raw_content=line,
            line_number=line_num,
            reason=reason
        )