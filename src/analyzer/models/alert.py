from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Alert(BaseModel):
    """
    Represents a detected security threat.
    """
    timestamp: datetime
    rule_name: str
    severity: Severity
    description: str
    source_ip: str
    raw_log: str

    model_config = ConfigDict(frozen=True)

    def __str__(self) -> str:
        return f"[{self.severity.value}] {self.rule_name}: {self.description} (IP: {self.source_ip})"