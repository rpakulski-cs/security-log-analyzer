# Security Log Analyzer

A Python CLI tool for analyzing security logs (Web Access & SSH/Auth). It detects potential threats such as SQL Injection, Brute Force attacks, and critical system errors, generating reports in text or JSON format.

## Quick Start

### Prerequisites
* Python 3.13.1+
* Install dependencies: `pip install -e`)

### Running the Analyzer

**Analyze files and display a text report (Default):**
python3 src/analyzer/main.py tests/test_data/webserver.log tests/test_data/auth.log

**Save the report to a JSON file:**
python3 src/analyzer/main.py tests/test_data/webserver.log -f json -o security_report.json

## Runing Tests
The project has full test coverage (Unit, Integration, E2E).

**Run all tests:**
pytest

**Run specific test categories:**
# Unit Tests (Fast, isolated logic)
pytest tests/analyzer/

# Integration Tests (Pipeline flow)
pytest tests/integration/

# End-to-End Tests (Full user scenarios)
pytest tests/e2e/

**Generate coverage report (requires pytest-cov):**


# About the Project

Security Log Analyzer is a modular tool designed for performance and extensibility. It automates the audit of log files to identify security incidents.

## Key Features

### Stream Processing:

Processes files line-by-line using generators, allowing analysis of log files larger than available RAM.

Merges logs from multiple sources into a single chronological event stream using heapq.merge.

### Detection Engine:

SQL Injection: Detects attack patterns in URLs (e.g., UNION SELECT, DROP TABLE).

SSH Brute Force: Stateful analysis – detects a series of failed login attempts from a single IP within a specific time window (e.g., 3 attempts in 60s).

Critical System Events: Detects keywords (e.g., shutdown, panic) even in malformed log lines.

### Intelligent Parsing:

Auto-detects log formats (Web Log vs. Syslog).

Fault Tolerance: Handles corrupted log lines (UnparsedLogEntry) with a timestamp estimation mechanism based on adjacent valid entries.

### Reporting:

Human-readable text reports on stdout or to a file.

Structured JSON reports for machine processing.

## Architecture

Models: Powered by Pydantic for strong typing and data validation.

Parsers: A factory pattern supporting various log formats.

Streamer: Manages file opening and time-series merging.

Engine: Contains the Rules logic and the Detector.

CLI: Entry point based on argparse.