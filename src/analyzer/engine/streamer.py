import heapq
from pathlib import Path
from contextlib import ExitStack
from typing import Iterator, List

from src.analyzer.models.base import BaseLogEntry
from src.analyzer.parsers.factory import ParserFactory

class LogStreamer:

    def stream_merged_logs(self, file_paths: List[Path]) -> Iterator[BaseLogEntry]:
        with ExitStack() as stack:
            generators = []
            
            for path in file_paths:
                if not path.exists():
                    print(f"Warning: file {path} not found, skipping.")
                    continue

                f = stack.enter_context(open(path, 'r', encoding='utf-8', errors='replace'))
                
                try:
                    log_iter = ParserFactory.get_parser_stream(path, f)
                    generators.append(log_iter)
                except ValueError as e:
                    print(f"Parser creation error for {path}: {e}")

            yield from heapq.merge(*generators)