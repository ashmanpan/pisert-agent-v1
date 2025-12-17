"""State definitions for the PSIRT Analysis LangGraph."""

from typing import TypedDict, List, Dict, Any, Optional, Annotated
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
import operator


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Likelihood(str, Enum):
    """Exploitation likelihood levels."""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class AttackVector(str, Enum):
    """Attack vector types."""
    NETWORK = "Network"
    ADJACENT = "Adjacent Network"
    LOCAL = "Local"
    PHYSICAL = "Physical"


@dataclass
class RiskAssessment:
    """Risk assessment for a vulnerability."""
    severity: Severity
    cvss_score: Optional[float]
    exploitability: Likelihood
    impact_description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "exploitability": self.exploitability.value,
            "impact_description": self.impact_description
        }


@dataclass
class Possibility:
    """Possibility/likelihood assessment for exploitation."""
    likelihood: Likelihood
    attack_vector: AttackVector
    requires_authentication: bool
    requires_user_interaction: bool
    complexity: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "likelihood": self.likelihood.value,
            "attack_vector": self.attack_vector.value,
            "requires_authentication": self.requires_authentication,
            "requires_user_interaction": self.requires_user_interaction,
            "complexity": self.complexity
        }


@dataclass
class Mitigation:
    """Mitigation recommendations for a vulnerability."""
    recommended_actions: List[str]
    patches_available: bool
    workarounds: List[str]
    upgrade_path: str
    estimated_effort: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recommended_actions": self.recommended_actions,
            "patches_available": self.patches_available,
            "workarounds": self.workarounds,
            "upgrade_path": self.upgrade_path,
            "estimated_effort": self.estimated_effort
        }


@dataclass
class VulnerabilityAnalysis:
    """Complete vulnerability analysis document."""
    advisory_id: str
    cve_ids: List[str]
    title: str
    when_is_this_a_problem: str
    clear_conditions: List[str]
    affected_products: List[str]
    risk_assessment: RiskAssessment
    possibility: Possibility
    mitigation: Mitigation
    affected_inventory: List[str]
    summary: str
    technical_details: str
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "cve_ids": self.cve_ids,
            "title": self.title,
            "analysis": {
                "when_is_this_a_problem": self.when_is_this_a_problem,
                "clear_conditions": self.clear_conditions,
                "affected_products": self.affected_products,
                "risk_assessment": self.risk_assessment.to_dict(),
                "possibility": self.possibility.to_dict(),
                "mitigation": self.mitigation.to_dict()
            },
            "affected_inventory": self.affected_inventory,
            "summary": self.summary,
            "technical_details": self.technical_details,
            "created_at": self.created_at
        }

    def to_document_text(self) -> str:
        """Convert analysis to text for embedding."""
        return f"""
SECURITY ADVISORY: {self.advisory_id}
Title: {self.title}
CVEs: {', '.join(self.cve_ids)}

WHEN IS THIS A PROBLEM:
{self.when_is_this_a_problem}

CONDITIONS:
{chr(10).join(f'- {c}' for c in self.clear_conditions)}

AFFECTED PRODUCTS:
{chr(10).join(f'- {p}' for p in self.affected_products)}

RISK ASSESSMENT:
- Severity: {self.risk_assessment.severity.value}
- CVSS Score: {self.risk_assessment.cvss_score}
- Exploitability: {self.risk_assessment.exploitability.value}
- Impact: {self.risk_assessment.impact_description}

POSSIBILITY:
- Likelihood: {self.possibility.likelihood.value}
- Attack Vector: {self.possibility.attack_vector.value}
- Requires Authentication: {self.possibility.requires_authentication}
- Requires User Interaction: {self.possibility.requires_user_interaction}
- Complexity: {self.possibility.complexity}

MITIGATION:
Recommended Actions:
{chr(10).join(f'- {a}' for a in self.mitigation.recommended_actions)}

Workarounds:
{chr(10).join(f'- {w}' for w in self.mitigation.workarounds) if self.mitigation.workarounds else '- None available'}

Upgrade Path: {self.mitigation.upgrade_path}
Patches Available: {'Yes' if self.mitigation.patches_available else 'No'}

AFFECTED INVENTORY:
{chr(10).join(f'- {i}' for i in self.affected_inventory) if self.affected_inventory else '- None identified'}

SUMMARY:
{self.summary}

TECHNICAL DETAILS:
{self.technical_details}
"""


@dataclass
class DeviceInfo:
    """Device information from inventory."""
    serial_no: int
    network_layer: str
    node: str
    router_type: str
    current_version: str
    image_version: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RawAdvisory:
    """Raw advisory data from API or scraper."""
    source: str  # "api" or "scraper"
    advisory_id: str
    title: str
    severity: str
    cve_ids: List[str]
    cvss_score: Optional[float]
    summary: str
    description: str
    affected_products: List[str]
    workarounds: List[str]
    fixed_software: List[str]
    url: str
    raw_data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def merge_lists(left: List, right: List) -> List:
    """Merge two lists, avoiding duplicates for dicts with 'advisory_id'."""
    result = list(left)
    seen_ids = {item.get('advisory_id') if isinstance(item, dict) else id(item) for item in left}

    for item in right:
        item_id = item.get('advisory_id') if isinstance(item, dict) else id(item)
        if item_id not in seen_ids:
            result.append(item)
            seen_ids.add(item_id)

    return result


class PSIRTState(TypedDict):
    """State for the PSIRT Analysis LangGraph workflow."""

    # Input data
    device_inventory: Annotated[List[Dict[str, Any]], operator.add]
    products_to_check: List[str]

    # Fetched data
    raw_advisories: Annotated[List[Dict[str, Any]], merge_lists]

    # Analysis results
    analyzed_vulnerabilities: Annotated[List[Dict[str, Any]], operator.add]
    risk_assessments: Annotated[List[Dict[str, Any]], operator.add]

    # Generated documents
    documents: Annotated[List[Dict[str, Any]], operator.add]

    # Processing status
    current_step: str
    errors: Annotated[List[str], operator.add]
    messages: Annotated[List[str], operator.add]


def create_initial_state() -> PSIRTState:
    """Create an initial empty state."""
    return PSIRTState(
        device_inventory=[],
        products_to_check=[],
        raw_advisories=[],
        analyzed_vulnerabilities=[],
        risk_assessments=[],
        documents=[],
        current_step="initialized",
        errors=[],
        messages=[]
    )
