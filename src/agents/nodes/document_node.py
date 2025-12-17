"""Document generation node for creating structured PSIRT documents."""

from typing import Dict, Any, List
from datetime import datetime
import json

from ..state import PSIRTState


def _generate_document(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a structured document from a risk assessment."""
    original = assessment.get("original_analysis", {})
    risk = assessment.get("risk_assessment", {})
    possibility = assessment.get("possibility", {})
    mitigation = assessment.get("mitigation", {})

    document = {
        "id": f"doc_{original.get('advisory_id', 'unknown')}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "advisory_id": original.get("advisory_id", ""),
        "cve_ids": original.get("cve_ids", []),
        "title": original.get("title", ""),
        "created_at": datetime.now().isoformat(),

        # Analysis Section
        "analysis": {
            "when_is_this_a_problem": original.get("when_is_this_a_problem", ""),
            "clear_conditions": original.get("clear_conditions", []),
            "affected_products": original.get("affected_products", []),
            "technical_summary": original.get("technical_summary", ""),
            "exploitation_scenario": original.get("exploitation_scenario", "")
        },

        # Risk Assessment Section
        "risk_assessment": {
            "severity": risk.get("severity", "Unknown"),
            "cvss_score": risk.get("cvss_score") or original.get("original_cvss_score"),
            "exploitability": risk.get("exploitability", "Unknown"),
            "impact_description": risk.get("impact_description", ""),
            "composite_risk_score": assessment.get("composite_risk_score", 0),
            "priority_rank": assessment.get("priority_rank", 0),
            "priority_level": assessment.get("priority_level", "")
        },

        # Possibility Section
        "possibility": {
            "likelihood": possibility.get("likelihood", "Unknown"),
            "attack_vector": possibility.get("attack_vector", "Unknown"),
            "requires_authentication": possibility.get("requires_authentication", False),
            "requires_user_interaction": possibility.get("requires_user_interaction", False),
            "complexity": possibility.get("complexity", "Unknown")
        },

        # Mitigation Section
        "mitigation": {
            "recommended_actions": mitigation.get("recommended_actions", []),
            "patches_available": mitigation.get("patches_available", False),
            "workarounds": mitigation.get("workarounds", []),
            "upgrade_path": mitigation.get("upgrade_path", ""),
            "estimated_effort": mitigation.get("estimated_effort", "Unknown"),
            "priority": mitigation.get("priority", "Medium")
        },

        # Inventory Section
        "affected_inventory": assessment.get("affected_inventory", []),
        "inventory_count": len(assessment.get("affected_inventory", [])),

        # Business Context
        "business_impact": assessment.get("business_impact", ""),
        "recommendation_summary": assessment.get("recommendation_summary", ""),

        # Metadata
        "metadata": {
            "source": original.get("source", "unknown"),
            "url": original.get("url", ""),
            "original_severity": original.get("original_severity", ""),
            "analysis_timestamp": datetime.now().isoformat()
        }
    }

    return document


def _generate_document_text(document: Dict[str, Any]) -> str:
    """Generate text representation of document for embedding."""
    analysis = document.get("analysis", {})
    risk = document.get("risk_assessment", {})
    possibility = document.get("possibility", {})
    mitigation = document.get("mitigation", {})

    text = f"""
================================================================================
CISCO SECURITY ADVISORY ANALYSIS
================================================================================

ADVISORY ID: {document.get('advisory_id', 'Unknown')}
TITLE: {document.get('title', '')}
CVEs: {', '.join(document.get('cve_ids', []))}

RISK LEVEL: {risk.get('severity', 'Unknown')} (Score: {risk.get('composite_risk_score', 'N/A')}/10)
PRIORITY: {risk.get('priority_level', '')}

--------------------------------------------------------------------------------
WHEN IS THIS A PROBLEM?
--------------------------------------------------------------------------------
{analysis.get('when_is_this_a_problem', 'Not specified')}

--------------------------------------------------------------------------------
CLEAR CONDITIONS FOR EXPLOITATION
--------------------------------------------------------------------------------
{chr(10).join(f'* {c}' for c in analysis.get('clear_conditions', ['Not specified']))}

--------------------------------------------------------------------------------
AFFECTED PRODUCTS
--------------------------------------------------------------------------------
{chr(10).join(f'* {p}' for p in analysis.get('affected_products', ['Not specified']))}

--------------------------------------------------------------------------------
RISK ASSESSMENT
--------------------------------------------------------------------------------
Severity: {risk.get('severity', 'Unknown')}
CVSS Score: {risk.get('cvss_score', 'N/A')}
Exploitability: {risk.get('exploitability', 'Unknown')}
Impact: {risk.get('impact_description', 'Not specified')}

--------------------------------------------------------------------------------
POSSIBILITY OF EXPLOITATION
--------------------------------------------------------------------------------
Likelihood: {possibility.get('likelihood', 'Unknown')}
Attack Vector: {possibility.get('attack_vector', 'Unknown')}
Requires Authentication: {'Yes' if possibility.get('requires_authentication') else 'No'}
Requires User Interaction: {'Yes' if possibility.get('requires_user_interaction') else 'No'}
Attack Complexity: {possibility.get('complexity', 'Unknown')}

--------------------------------------------------------------------------------
MITIGATION RECOMMENDATIONS
--------------------------------------------------------------------------------
Priority: {mitigation.get('priority', 'Medium')}
Estimated Effort: {mitigation.get('estimated_effort', 'Unknown')}
Patches Available: {'Yes' if mitigation.get('patches_available') else 'No'}

RECOMMENDED ACTIONS:
{chr(10).join(f'{i+1}. {a}' for i, a in enumerate(mitigation.get('recommended_actions', ['No specific actions'])))}

WORKAROUNDS:
{chr(10).join(f'* {w}' for w in mitigation.get('workarounds', ['None available'])) if mitigation.get('workarounds') else '* None available'}

UPGRADE PATH: {mitigation.get('upgrade_path', 'Not specified')}

--------------------------------------------------------------------------------
AFFECTED INVENTORY
--------------------------------------------------------------------------------
{chr(10).join(f'* {d}' for d in document.get('affected_inventory', ['None identified'])) if document.get('affected_inventory') else '* No inventory devices affected'}

Total Affected Devices: {document.get('inventory_count', 0)}

--------------------------------------------------------------------------------
BUSINESS IMPACT
--------------------------------------------------------------------------------
{document.get('business_impact', 'Not assessed')}

--------------------------------------------------------------------------------
RECOMMENDATION SUMMARY
--------------------------------------------------------------------------------
{document.get('recommendation_summary', 'No summary available')}

--------------------------------------------------------------------------------
TECHNICAL SUMMARY
--------------------------------------------------------------------------------
{analysis.get('technical_summary', 'Not available')}

--------------------------------------------------------------------------------
EXPLOITATION SCENARIO
--------------------------------------------------------------------------------
{analysis.get('exploitation_scenario', 'Not described')}

================================================================================
Source: {document.get('metadata', {}).get('source', 'Unknown')}
URL: {document.get('metadata', {}).get('url', 'N/A')}
Analysis Date: {document.get('created_at', 'Unknown')}
================================================================================
"""
    return text


def _generate_summary_document(documents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate an executive summary document."""
    critical = [d for d in documents if d.get("risk_assessment", {}).get("severity") == "Critical"]
    high = [d for d in documents if d.get("risk_assessment", {}).get("severity") == "High"]
    medium = [d for d in documents if d.get("risk_assessment", {}).get("severity") == "Medium"]
    low = [d for d in documents if d.get("risk_assessment", {}).get("severity") == "Low"]

    total_affected = sum(d.get("inventory_count", 0) for d in documents)

    summary = {
        "id": f"summary_{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "type": "executive_summary",
        "title": f"PSIRT Analysis Summary - {datetime.now().strftime('%Y-%m-%d')}",
        "created_at": datetime.now().isoformat(),

        "statistics": {
            "total_advisories": len(documents),
            "critical_count": len(critical),
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(low),
            "total_affected_devices": total_affected
        },

        "critical_advisories": [
            {
                "advisory_id": d.get("advisory_id"),
                "title": d.get("title"),
                "affected_devices": d.get("inventory_count", 0),
                "recommendation": d.get("recommendation_summary", "")[:200]
            }
            for d in critical[:10]  # Top 10 critical
        ],

        "high_priority_advisories": [
            {
                "advisory_id": d.get("advisory_id"),
                "title": d.get("title"),
                "affected_devices": d.get("inventory_count", 0)
            }
            for d in high[:10]  # Top 10 high
        ],

        "top_recommendations": [
            d.get("recommendation_summary", "")
            for d in sorted(documents, key=lambda x: x.get("risk_assessment", {}).get("composite_risk_score", 0), reverse=True)[:5]
        ]
    }

    return summary


def generate_document_node(state: PSIRTState) -> Dict[str, Any]:
    """
    Generate structured documents from risk assessments.

    This node:
    1. Takes risk assessments from state
    2. Generates structured documents for each assessment
    3. Creates text representations for embedding
    4. Generates an executive summary
    5. Returns documents ready for storage
    """
    messages = ["Starting document generation..."]
    errors = []
    documents = []

    assessments = state.get("risk_assessments", [])

    if not assessments:
        messages.append("No risk assessments to document")
        return {
            "documents": [],
            "current_step": "documented",
            "messages": messages,
            "errors": errors
        }

    messages.append(f"Generating documents for {len(assessments)} assessments...")

    # Generate individual documents
    for assessment in assessments:
        try:
            doc = _generate_document(assessment)
            doc["text_content"] = _generate_document_text(doc)
            documents.append(doc)
        except Exception as e:
            errors.append(f"Error generating document for {assessment.get('advisory_id', 'Unknown')}: {str(e)}")

    # Generate summary document
    try:
        summary = _generate_summary_document(documents)
        summary["text_content"] = json.dumps(summary, indent=2)
        documents.insert(0, summary)  # Add summary at the beginning
        messages.append("Generated executive summary")
    except Exception as e:
        errors.append(f"Error generating summary: {str(e)}")

    messages.append(f"Generated {len(documents)} documents")

    return {
        "documents": documents,
        "current_step": "documented",
        "messages": messages,
        "errors": errors
    }
