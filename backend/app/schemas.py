from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    source: str = "api"
    network: bool = True     # allow WHOIS/TLS lookups for this request


class DomScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    title: str = ""
    text: str = Field("", max_length=20000)
    favicon_url: Optional[str] = None
    features: Dict[str, float] = Field(default_factory=dict)
    source: str = "extension"


class LayerOut(BaseModel):
    name: str
    score: Optional[float]
    weight: float
    contribution: float
    available: bool
    reasons: List[str]
    details: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scan_id: Optional[int]
    url: str
    domain: str
    stage: str
    risk: float
    verdict: Literal["ALLOW", "WARN", "RESTRICT", "BLOCK"]
    trust: str
    impersonated_brand: Optional[str] = None
    reasons: List[str]
    layers: List[LayerOut]
    latency_ms: float
    cached: bool = False
    created_at: Optional[datetime] = None


class FeedbackRequest(BaseModel):
    url: str
    label: Literal["phishing", "legitimate"]
    scan_id: Optional[int] = None
    comment: Optional[str] = None


class OverrideRequest(BaseModel):
    scan_id: int
