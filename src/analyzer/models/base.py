from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any, Union
from pydantic import BaseModel, Field, ConfigDict, IPvAnyAddress

class LogType(str, Enum):
    SSH = "ssh"
    WEB = "web"
    UNPARSED = "unparsed"
    GENERIC = "generic"

class BaseLogEntry(BaseModel):
    timestamp: datetime
    log_type: LogType
    raw_content: str = Field(repr=False)
    is_timestamp_estimated: bool = False
    line_number: Optional[int] = None
    
    model_config = ConfigDict(frozen=True, extra='ignore')

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, BaseLogEntry):
            return NotImplemented
        return self.timestamp < other.timestamp

class UnparsedLogEntry(BaseLogEntry):
    """Model for lines that failed regex parsing."""
    log_type: LogType = LogType.UNPARSED
    reason: str = "Regex mismatch or validation error"

# --- Existing specific models updated with line_number ---

class WebLogEntry(BaseLogEntry):
    log_type: LogType = LogType.WEB
    source_ip: IPvAnyAddress
    http_method: str
    request_path: str
    status_code: int
    response_size_bytes: int

class SSHLogEntry(BaseLogEntry):
    log_type: LogType = LogType.SSH
    hostname: str
    process_name: str
    pid: Optional[int] = None
    message: str
    source_ip: Optional[IPvAnyAddress] = None
    user: Optional[str] = None
    port: Optional[int] = None

# Type alias for easier type hinting
LogEntry = Union[WebLogEntry, SSHLogEntry, UnparsedLogEntry]