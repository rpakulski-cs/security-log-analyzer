import json
import sys
from abc import ABC, abstractmethod
from typing import Iterator, TextIO

from src.analyzer.models.alert import Alert

class ReportWriter(ABC):
    """Interfejs dla strategii raportowania."""
    
    @abstractmethod
    def write(self, alerts: Iterator[Alert], destination: TextIO):
        """Zapisuje alerty do podanego strumienia (pliku lub stdout)."""
        pass

class ConsoleWriter(ReportWriter):
    """
    Wypisuje alerty w formacie czytelnym dla człowieka.
    Działa w trybie strumieniowym (wyświetla alerty natychmiast po wykryciu).
    """
    def write(self, alerts: Iterator[Alert], destination: TextIO = sys.stdout):
        count = 0
        destination.write("\n--- SECURITY ANALYSIS REPORT ---\n")
        
        for alert in alerts:
            count += 1
            # Proste formatowanie tekstu
            header = f"[{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] [{alert.severity.value}] {alert.rule_name}"
            destination.write(f"{header}\n")
            destination.write(f"    IP: {alert.source_ip}\n")
            destination.write(f"    Details: {alert.description}\n")
            destination.write("-" * 60 + "\n")
            destination.flush() # Ważne przy potokach (pipes)

        destination.write(f"\nAnalysis complete. Total threats detected: {count}\n")

class JsonWriter(ReportWriter):
    """
    Zapisuje alerty w formacie JSON.
    Uwaga: Aby wygenerować poprawny JSON (tablicę obiektów), musi skonsumować cały iterator.
    """
    def write(self, alerts: Iterator[Alert], destination: TextIO = sys.stdout):
        # Konwertujemy alerty na słowniki przy użyciu Pydantic (mode='json' obsługuje daty)
        data = [alert.model_dump(mode='json') for alert in alerts]
        
        # Zapisujemy sformatowany JSON
        json.dump(data, destination, indent=2, ensure_ascii=False)
        destination.write("\n") # Nowa linia na końcu pliku