from datetime import datetime
from enum import Enum
from typing import Optional, Any
import ipaddress

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator, ConfigDict

class LogType(str, Enum):
    SSH = "ssh"
    WEB = "web"
    GENERIC = "generic"

class BaseLogEntry(BaseModel):
    timestamp: datetime
    log_type: LogType
    raw_content: str = Field(repr=False) 
    
    model_config = ConfigDict(frozen=True, extra='ignore')

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, BaseLogEntry):
            return NotImplemented
        return self.timestamp < other.timestamp

class WebLogEntry(BaseLogEntry):
    log_type: LogType = LogType.WEB
    
    source_ip: IPvAnyAddress
    http_method: str
    request_path: str
    status_code: int
    response_size_bytes: int

    @field_validator('status_code')
    @classmethod
    def validate_status(cls, v: int) -> int:
        if not (100 <= v <= 599):
            raise ValueError(f"Invalid HTTP status code: {v}")
        return v

class SSHLogEntry(BaseLogEntry):
    log_type: LogType = LogType.SSH
    
    hostname: str
    process_name: str
    pid: Optional[int] = None
    message: str
    
    source_ip: Optional[IPvAnyAddress] = None
    user: Optional[str] = None
    port: Optional[int] = None