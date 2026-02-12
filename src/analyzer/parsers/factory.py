from pathlib import Path
from typing import Iterable, Iterator

from src.analyzer.models.base import BaseLogEntry
from src.analyzer.parsers.syslog import SyslogParser
from src.analyzer.parsers.web import WebLogParser

class ParserFactory:

    @staticmethod
    def get_parser_stream(file_path: Path, file_handle: Iterable[str]) -> Iterator[BaseLogEntry]:
        filename = file_path.name.lower()

        if "auth" in filename or "syslog" in filename:
            return SyslogParser(year=2025).parse(file_handle)
        
        elif "web" in filename or "access" in filename or "nginx" in filename:
            return WebLogParser().parse(file_handle)
        
        else:
            raise ValueError(f"Unrecognized file type: {filename}")