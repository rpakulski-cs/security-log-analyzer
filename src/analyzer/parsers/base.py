import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from src.analyzer.models.base import LogEntry, UnparsedLogEntry

logger = logging.getLogger(__name__)

class BaseParser(ABC):
    """
    Abstrakcyjna klasa bazowa dla wszystkich parserów logów.
    Zapewnia mechanizm 'Stateful Timestamp' dla obsługi błędnych linii.
    """
    def __init__(self):
        # Przechowuje ostatni poprawny znacznik czasu dla celów estymacji [Senior Tip]
        self.last_valid_timestamp: Optional[datetime] = None

    @abstractmethod
    def parse(self, lines: Iterable[str]) -> Iterator[LogEntry]:
        """Główna metoda parsująca strumień linii."""
        pass

    def _handle_unparsed(self, line: str, line_num: int, reason: str) -> UnparsedLogEntry:
        """
        Uniwersalna metoda obsługi linii, których nie udało się sparsować.
        Zapewnia ciągłość chronologiczną raportu.
        """
        return UnparsedLogEntry(
            timestamp=self.last_valid_timestamp or datetime.now(timezone.utc),
            is_timestamp_estimated=True if self.last_valid_timestamp else False,
            raw_content=line,
            line_number=line_num,
            reason=reason
        )