import json
import sys
from abc import ABC, abstractmethod
from typing import Iterator, TextIO

from src.analyzer.models.alert import Alert

class ReportWriter(ABC):
    
    @abstractmethod
    def write(self, alerts: Iterator[Alert], destination: TextIO):
        pass

class ConsoleWriter(ReportWriter):
    def write(self, alerts: Iterator[Alert], destination: TextIO = sys.stdout):
        count = 0
        destination.write("\n--- SECURITY ANALYSIS REPORT ---\n")
        
        for alert in alerts:
            count += 1
            header = f"[{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] [{alert.severity.value}] {alert.rule_name}"
            destination.write(f"{header}\n")
            destination.write(f"    IP: {alert.source_ip}\n")
            destination.write(f"    Details: {alert.description}\n")
            destination.write("-" * 60 + "\n")
            destination.flush()

        destination.write(f"\nAnalysis complete. Total threats detected: {count}\n")

class JsonWriter(ReportWriter):
    def write(self, alerts: Iterator[Alert], destination: TextIO = sys.stdout):
        data = [alert.model_dump(mode='json') for alert in alerts]
        
        json.dump(data, destination, indent=2, ensure_ascii=False)
        destination.write("\n")