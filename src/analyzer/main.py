import argparse
import sys
import logging
from pathlib import Path

# Dodajemy katalog nadrzędny do ścieżki, jeśli uruchamiamy jako skrypt
# (choć w produkcji używa się 'python -m src.analyzer.main')
sys.path.append(".")

from src.analyzer.engine.streamer import LogStreamer
from src.analyzer.engine.detector import ThreatDetector
from src.analyzer.engine.rules import SQLInjectionRule, BruteForceRule, KeywordAlertRule
from src.analyzer.output.writer import ConsoleWriter, JsonWriter

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("main")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer CLI Tool",
        epilog="Example: python src/analyzer/main.py tests/test_data/auth.log -f json"
    )
    
    parser.add_argument(
        "files", 
        nargs="+", 
        type=Path, 
        help="Path to log files (auth.log, access.log, etc.)"
    )
    
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output file path. If not specified, prints to stdout."
    )
    
    return parser.parse_args()

def main():
    args = parse_args()

    valid_files = [f for f in args.files if f.exists()]
    if not valid_files:
        logger.error("No valid input files provided.")
        sys.exit(1)
        
    if len(valid_files) < len(args.files):
        logger.warning(f"Some files were not found and will be skipped.")

    rules = [
        SQLInjectionRule(),
        BruteForceRule(max_attempts=3, window_seconds=60),
        KeywordAlertRule()
    ]
    
    streamer = LogStreamer()
    detector = ThreatDetector(rules)
    
    writer = JsonWriter() if args.format == "json" else ConsoleWriter()

    try:
        log_stream = streamer.stream_merged_logs(valid_files)
        alert_stream = detector.analyze_stream(log_stream)
        
        if args.output:
            logger.info(f"Writing report to {args.output} file.")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                writer.write(alert_stream, destination=f)
        else:
            writer.write(alert_stream, destination=sys.stdout)

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()