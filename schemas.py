from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class IOCType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"
    email = "email"


class SeverityLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


# ── Chat ──────────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(user|assistant)$")
    content: str


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    history: List[ChatMessage] = []


class ChatResponse(BaseModel):
    response: str
    model: str


# ── IOC Analysis ──────────────────────────────────────────────────────────────

class IOCRequest(BaseModel):
    indicator: str = Field(..., description="The IOC value (IP, domain, hash, URL, email)")
    ioc_type: IOCType
    context: Optional[str] = Field(None, description="Additional context about where this IOC was found")


class IOCResponse(BaseModel):
    indicator: str
    ioc_type: str
    severity: SeverityLevel
    analysis: str
    recommendations: List[str]
    mitre_techniques: List[str]


# ── CVE Analysis ──────────────────────────────────────────────────────────────

class CVERequest(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$", description="CVE identifier e.g. CVE-2024-1234")
    context: Optional[str] = Field(None, description="Your environment or technology stack context")


class CVEResponse(BaseModel):
    cve_id: str
    severity: SeverityLevel
    analysis: str
    affected_systems: List[str]
    remediation: List[str]
    exploitability: str


# ── Malware Analysis ─────────────────────────────────────────────────────────

class MalwareRequest(BaseModel):
    sample_info: str = Field(..., description="Hash, filename, or behavioral description of the sample")
    behavior: Optional[str] = Field(None, description="Observed behavior or sandbox output")


class MalwareResponse(BaseModel):
    classification: str
    severity: SeverityLevel
    analysis: str
    iocs: List[str]
    mitre_techniques: List[str]
    recommendations: List[str]


# ── Threat Report ────────────────────────────────────────────────────────────

class ThreatReportRequest(BaseModel):
    raw_data: str = Field(..., description="Raw logs, alerts, or threat data to analyze")
    environment: Optional[str] = Field(None, description="Description of your environment")


class ThreatReportResponse(BaseModel):
    summary: str
    severity: SeverityLevel
    findings: List[str]
    mitre_techniques: List[str]
    recommendations: List[str]
