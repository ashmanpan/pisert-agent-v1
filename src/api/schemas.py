"""Pydantic schemas for API request/response models."""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity level enumeration."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


# ============== Request Models ==============

class QueryRequest(BaseModel):
    """Request model for RAG queries."""
    question: str = Field(..., description="The security question to ask", min_length=5)
    limit: int = Field(default=5, description="Number of documents to retrieve", ge=1, le=20)
    severity_filter: Optional[SeverityLevel] = Field(default=None, description="Filter by severity level")
    min_risk_score: Optional[float] = Field(default=None, description="Minimum risk score (1-10)", ge=1, le=10)


class AnalysisRequest(BaseModel):
    """Request model for triggering PSIRT analysis."""
    products: Optional[List[str]] = Field(default=None, description="List of products to analyze")
    include_scraping: bool = Field(default=True, description="Include web scraping")
    severity_threshold: Optional[SeverityLevel] = Field(default=None, description="Minimum severity to include")


class InventoryUploadRequest(BaseModel):
    """Request model for inventory data."""
    inventory: List[Dict[str, Any]] = Field(..., description="List of device inventory items")


class CVEQueryRequest(BaseModel):
    """Request model for CVE-specific queries."""
    cve_id: str = Field(..., description="CVE identifier", pattern=r"CVE-\d{4}-\d+")


class ProductQueryRequest(BaseModel):
    """Request model for product-specific queries."""
    product: str = Field(..., description="Product name", min_length=2)
    severity: Optional[SeverityLevel] = Field(default=None, description="Severity filter")


# ============== Response Models ==============

class SourceInfo(BaseModel):
    """Source information for a response."""
    advisory_id: str
    title: str
    severity: str
    risk_score: float
    similarity_score: float
    url: Optional[str] = None


class QueryResponse(BaseModel):
    """Response model for RAG queries."""
    answer: str
    sources: List[SourceInfo]
    query: str
    confidence: str
    timestamp: datetime = Field(default_factory=datetime.now)


class RiskAssessmentInfo(BaseModel):
    """Risk assessment information."""
    severity: str
    cvss_score: Optional[float]
    exploitability: str
    impact_description: str
    composite_risk_score: float
    priority_level: str


class MitigationInfo(BaseModel):
    """Mitigation information."""
    recommended_actions: List[str]
    patches_available: bool
    workarounds: List[str]
    upgrade_path: str
    estimated_effort: str


class AdvisoryResponse(BaseModel):
    """Response model for advisory information."""
    id: str
    advisory_id: str
    title: str
    cve_ids: List[str]
    severity: str
    risk_score: float
    priority_level: str
    when_is_this_a_problem: Optional[str] = None
    clear_conditions: List[str] = []
    affected_products: List[str] = []
    risk_assessment: Optional[RiskAssessmentInfo] = None
    mitigation: Optional[MitigationInfo] = None
    affected_inventory: List[str] = []
    created_at: Optional[datetime] = None
    url: Optional[str] = None


class AdvisoryListResponse(BaseModel):
    """Response model for advisory list."""
    advisories: List[AdvisoryResponse]
    total: int
    page: int
    limit: int


class InventoryItem(BaseModel):
    """Device inventory item."""
    serial_no: int
    network_layer: str
    node: str
    router_type: str
    current_version: str
    image_version: str


class InventoryResponse(BaseModel):
    """Response model for inventory."""
    items: List[InventoryItem]
    total: int
    products: List[str]


class AnalysisStatusResponse(BaseModel):
    """Response model for analysis status."""
    status: str
    current_step: str
    messages: List[str]
    errors: List[str]
    documents_generated: int
    advisories_processed: int


class AnalysisResponse(BaseModel):
    """Response model for completed analysis."""
    status: str
    documents_count: int
    advisories_analyzed: int
    critical_count: int
    high_count: int
    affected_devices: int
    messages: List[str]
    errors: List[str]


class StatisticsResponse(BaseModel):
    """Response model for statistics."""
    total_documents: int
    severity_distribution: Dict[str, int]
    collection_status: str


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    qdrant_connected: bool
    llm_configured: bool


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
