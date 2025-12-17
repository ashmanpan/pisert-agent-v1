"""Risk assessment node for evaluating vulnerability risks."""

import json
from typing import Dict, Any, List, Optional
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser

from ..state import PSIRTState, Severity, Likelihood, AttackVector
from ...config import settings


RISK_ASSESSMENT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a cybersecurity risk analyst specializing in network infrastructure.
Your task is to assess the risk of security vulnerabilities and provide actionable recommendations.

For each vulnerability, evaluate:
1. RISK: Overall risk level based on severity, exploitability, and business impact
2. POSSIBILITY: Likelihood of exploitation in a real-world scenario
3. MITIGATION: Specific, prioritized remediation steps

Consider factors like:
- Network exposure (internet-facing vs internal)
- Authentication requirements
- Complexity of exploitation
- Availability of exploit code
- Business criticality of affected systems

Be specific and practical. Prioritize recommendations by urgency."""),

    ("human", """Assess the risk for the following analyzed vulnerability:

Advisory ID: {advisory_id}
Title: {title}
CVEs: {cve_ids}
Original Severity: {severity}
CVSS Score: {cvss_score}

When is this a problem:
{when_is_this_a_problem}

Clear Conditions:
{clear_conditions}

Affected Products:
{affected_products}

Technical Summary:
{technical_summary}

Exploitation Scenario:
{exploitation_scenario}

Affected Inventory (from organization):
{affected_inventory}

Provide your risk assessment in JSON format:
{{
    "advisory_id": "string",
    "risk_assessment": {{
        "severity": "Critical|High|Medium|Low",
        "cvss_score": number or null,
        "exploitability": "High|Medium|Low",
        "impact_description": "detailed impact description"
    }},
    "possibility": {{
        "likelihood": "High|Medium|Low",
        "attack_vector": "Network|Adjacent Network|Local|Physical",
        "requires_authentication": boolean,
        "requires_user_interaction": boolean,
        "complexity": "Low|Medium|High"
    }},
    "mitigation": {{
        "recommended_actions": ["action 1", "action 2", ...],
        "patches_available": boolean,
        "workarounds": ["workaround 1", ...],
        "upgrade_path": "recommended upgrade version",
        "estimated_effort": "Low|Medium|High",
        "priority": "Immediate|High|Medium|Low"
    }},
    "business_impact": "description of business impact",
    "risk_score": number (1-10),
    "recommendation_summary": "one paragraph summary of recommended actions"
}}""")
])


def _create_llm() -> ChatAnthropic:
    """Create Claude LLM instance."""
    return ChatAnthropic(
        model="claude-sonnet-4-20250514",
        anthropic_api_key=settings.anthropic_api_key,
        temperature=0.1,
        max_tokens=4096
    )


def _assess_single_vulnerability(
    llm: ChatAnthropic,
    analysis: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Assess risk for a single analyzed vulnerability."""
    try:
        chain = RISK_ASSESSMENT_PROMPT | llm | JsonOutputParser()

        result = chain.invoke({
            "advisory_id": analysis.get("advisory_id", "Unknown"),
            "title": analysis.get("title", ""),
            "cve_ids": ", ".join(analysis.get("cve_ids", [])),
            "severity": analysis.get("original_severity", "Unknown"),
            "cvss_score": analysis.get("original_cvss_score", "N/A"),
            "when_is_this_a_problem": analysis.get("when_is_this_a_problem", ""),
            "clear_conditions": "\n".join(f"- {c}" for c in analysis.get("clear_conditions", [])),
            "affected_products": "\n".join(f"- {p}" for p in analysis.get("affected_products", [])),
            "technical_summary": analysis.get("technical_summary", ""),
            "exploitation_scenario": analysis.get("exploitation_scenario", ""),
            "affected_inventory": "\n".join(f"- {d}" for d in analysis.get("affected_inventory", [])) or "None identified"
        })

        return result

    except Exception as e:
        print(f"Error assessing risk for {analysis.get('advisory_id')}: {e}")
        return None


def _calculate_composite_risk_score(assessment: Dict[str, Any]) -> float:
    """Calculate a composite risk score from assessment components."""
    score = 0.0

    # Severity contribution (0-4)
    severity = assessment.get("risk_assessment", {}).get("severity", "Medium")
    severity_scores = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    score += severity_scores.get(severity, 2)

    # Exploitability contribution (0-3)
    exploitability = assessment.get("risk_assessment", {}).get("exploitability", "Medium")
    exploit_scores = {"High": 3, "Medium": 2, "Low": 1}
    score += exploit_scores.get(exploitability, 2)

    # Likelihood contribution (0-2)
    likelihood = assessment.get("possibility", {}).get("likelihood", "Medium")
    likelihood_scores = {"High": 2, "Medium": 1, "Low": 0.5}
    score += likelihood_scores.get(likelihood, 1)

    # Complexity reduction (0-1)
    complexity = assessment.get("possibility", {}).get("complexity", "Medium")
    complexity_adjustments = {"Low": 0, "Medium": -0.5, "High": -1}
    score += complexity_adjustments.get(complexity, -0.5)

    # Normalize to 1-10 scale
    normalized = min(10, max(1, (score / 9) * 10))
    return round(normalized, 1)


def _prioritize_mitigations(assessments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort assessments by risk and add priority rankings."""
    # Sort by risk score descending
    sorted_assessments = sorted(
        assessments,
        key=lambda x: x.get("composite_risk_score", 0),
        reverse=True
    )

    # Add priority rankings
    for i, assessment in enumerate(sorted_assessments):
        assessment["priority_rank"] = i + 1
        risk_score = assessment.get("composite_risk_score", 5)

        if risk_score >= 8:
            assessment["priority_level"] = "Critical - Immediate Action Required"
        elif risk_score >= 6:
            assessment["priority_level"] = "High - Action Within 24-48 Hours"
        elif risk_score >= 4:
            assessment["priority_level"] = "Medium - Action Within 1 Week"
        else:
            assessment["priority_level"] = "Low - Monitor and Plan"

    return sorted_assessments


def assess_risk_node(state: PSIRTState) -> Dict[str, Any]:
    """
    Assess risk for analyzed vulnerabilities.

    This node:
    1. Takes analyzed vulnerabilities from state
    2. Uses Claude to assess risk levels
    3. Calculates composite risk scores
    4. Prioritizes mitigations
    5. Returns risk assessments with:
       - Risk assessment (severity, exploitability, impact)
       - Possibility (likelihood, attack vector, complexity)
       - Mitigation (actions, workarounds, upgrade path)
       - Priority ranking
    """
    messages = ["Starting risk assessment..."]
    errors = []
    assessments = []

    analyzed = state.get("analyzed_vulnerabilities", [])

    if not analyzed:
        messages.append("No analyzed vulnerabilities to assess")
        return {
            "risk_assessments": [],
            "current_step": "risk_assessed",
            "messages": messages,
            "errors": errors
        }

    messages.append(f"Assessing risk for {len(analyzed)} vulnerabilities...")

    # Create LLM
    try:
        llm = _create_llm()
    except Exception as e:
        errors.append(f"Failed to create LLM: {str(e)}")
        return {
            "risk_assessments": [],
            "current_step": "risk_assessed",
            "messages": messages,
            "errors": errors
        }

    # Assess each vulnerability
    for i, analysis in enumerate(analyzed):
        try:
            messages.append(f"Assessing {i+1}/{len(analyzed)}: {analysis.get('advisory_id', 'Unknown')}")

            assessment = _assess_single_vulnerability(llm, analysis)

            if assessment:
                # Calculate composite score
                assessment["composite_risk_score"] = _calculate_composite_risk_score(assessment)

                # Merge with original analysis
                assessment["original_analysis"] = analysis
                assessment["affected_inventory"] = analysis.get("affected_inventory", [])

                assessments.append(assessment)
            else:
                errors.append(f"Failed to assess {analysis.get('advisory_id')}")

        except Exception as e:
            errors.append(f"Error assessing {analysis.get('advisory_id', 'Unknown')}: {str(e)}")

    # Prioritize
    prioritized = _prioritize_mitigations(assessments)
    messages.append(f"Completed risk assessment for {len(prioritized)} vulnerabilities")

    # Summary
    critical_count = sum(1 for a in prioritized if a.get("composite_risk_score", 0) >= 8)
    high_count = sum(1 for a in prioritized if 6 <= a.get("composite_risk_score", 0) < 8)

    messages.append(f"Risk Summary: {critical_count} Critical, {high_count} High priority items")

    return {
        "risk_assessments": prioritized,
        "current_step": "risk_assessed",
        "messages": messages,
        "errors": errors
    }
