from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, HttpUrl

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    description: str
    url: str
    evidence: Optional[str] = None

class PageResponse(BaseModel):
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    discovered_links: List[str] = []