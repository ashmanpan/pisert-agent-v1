"""Analyze node for vulnerability analysis using Claude LLM."""

import json
from typing import Dict, Any, List, Optional
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field

from ..state import PSIRTState
from ...config import settings


class VulnerabilityConditions(BaseModel):
    """Model for vulnerability conditions."""
    when_is_this_a_problem: str = Field(description="When this vulnerability becomes a problem")
    clear_conditions: List[str] = Field(description="List of clear conditions for exploitation")
    affected_versions: List[str] = Field(description="List of affected software versions")
    attack_prerequisites: List[str] = Field(description="Prerequisites for successful attack")


class AnalyzedVulnerability(BaseModel):
    """Model for analyzed vulnerability output."""
    advisory_id: str = Field(description="The Cisco advisory ID")
    title: str = Field(description="Advisory title")
    cve_ids: List[str] = Field(description="List of CVE IDs")

    when_is_this_a_problem: str = Field(
        description="Detailed explanation of when this vulnerability is a problem"
    )
    clear_conditions: List[str] = Field(
        description="Clear, specific conditions under which the vulnerability can be exploited"
    )
    affected_products: List[str] = Field(
        description="List of affected products and versions"
    )

    technical_summary: str = Field(
        description="Technical summary of the vulnerability"
    )
    exploitation_scenario: str = Field(
        description="Realistic exploitation scenario"
    )


ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a senior cybersecurity analyst specializing in Cisco network infrastructure security.
Your task is to analyze security advisories and provide detailed, actionable analysis.

For each advisory, you must provide:
1. WHEN IS THIS A PROBLEM: Clearly explain the conditions under which this vulnerability affects systems
2. CLEAR CONDITIONS: List specific, verifiable conditions that must be met for exploitation
3. AFFECTED PRODUCTS: List all affected products and their versions
4. TECHNICAL SUMMARY: Provide a technical explanation suitable for security engineers
5. EXPLOITATION SCENARIO: Describe a realistic attack scenario

Be specific and technical. Avoid vague statements. Focus on actionable information."""),

    ("human", """Analyze the following Cisco security advisory:

Advisory ID: {advisory_id}
Title: {title}
CVEs: {cve_ids}
Severity: {severity}
CVSS Score: {cvss_score}

Summary:
{summary}

Description:
{description}

Affected Products:
{affected_products}

Workarounds:
{workarounds}

Fixed Software:
{fixed_software}

Provide your analysis in JSON format with the following structure:
{{
    "advisory_id": "string",
    "title": "string",
    "cve_ids": ["string"],
    "when_is_this_a_problem": "detailed explanation",
    "clear_conditions": ["condition 1", "condition 2", ...],
    "affected_products": ["product 1", "product 2", ...],
    "technical_summary": "technical explanation",
    "exploitation_scenario": "realistic attack scenario"
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


def _analyze_single_advisory(
    llm: ChatAnthropic,
    advisory: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Analyze a single advisory using Claude."""
    try:
        # Prepare input
        chain = ANALYSIS_PROMPT | llm | JsonOutputParser()

        result = chain.invoke({
            "advisory_id": advisory.get("advisory_id", "Unknown"),
            "title": advisory.get("title", ""),
            "cve_ids": ", ".join(advisory.get("cve_ids", [])),
            "severity": advisory.get("severity", "Unknown"),
            "cvss_score": advisory.get("cvss_score", "N/A"),
            "summary": advisory.get("summary", "")[:2000],
            "description": advisory.get("description", "")[:3000],
            "affected_products": "\n".join(advisory.get("affected_products", [])),
            "workarounds": "\n".join(advisory.get("workarounds", [])),
            "fixed_software": "\n".join(advisory.get("fixed_software", []))
        })

        # Add original data
        result["original_severity"] = advisory.get("severity", "Unknown")
        result["original_cvss_score"] = advisory.get("cvss_score")
        result["source"] = advisory.get("source", "unknown")
        result["url"] = advisory.get("url", "")

        return result

    except Exception as e:
        print(f"Error analyzing advisory {advisory.get('advisory_id')}: {e}")
        return None


def _match_inventory(
    analysis: Dict[str, Any],
    inventory: List[Dict[str, Any]]
) -> List[str]:
    """Match analyzed vulnerability against device inventory."""
    affected_devices = []
    affected_products = analysis.get("affected_products", [])

    for device in inventory:
        device_type = device.get("router_type", "").lower()
        device_version = device.get("current_version", "").lower()

        for product in affected_products:
            product_lower = product.lower()

            # Check if device type matches
            if any(dt in product_lower for dt in [device_type, device_type.replace("-", "")]):
                # Check version if specified in product
                if device_version and device_version in product_lower:
                    affected_devices.append(
                        f"{device.get('node', 'Unknown')} - {device.get('router_type', '')} ({device.get('current_version', '')})"
                    )
                elif not any(char.isdigit() for char in product):
                    # Product doesn't specify version, include device
                    affected_devices.append(
                        f"{device.get('node', 'Unknown')} - {device.get('router_type', '')} ({device.get('current_version', '')})"
                    )

    return list(set(affected_devices))


def analyze_vulnerability_node(state: PSIRTState) -> Dict[str, Any]:
    """
    Analyze vulnerabilities using Claude LLM.

    This node:
    1. Takes raw advisories from state
    2. Uses Claude to perform deep analysis
    3. Matches against device inventory
    4. Returns analyzed vulnerabilities with:
       - When is this a problem
       - Clear conditions
       - Affected products
       - Technical summary
       - Exploitation scenario
    """
    messages = ["Starting vulnerability analysis..."]
    errors = []
    analyzed = []

    raw_advisories = state.get("raw_advisories", [])
    inventory = state.get("device_inventory", [])

    if not raw_advisories:
        messages.append("No advisories to analyze")
        return {
            "analyzed_vulnerabilities": [],
            "current_step": "analyzed",
            "messages": messages,
            "errors": errors
        }

    messages.append(f"Analyzing {len(raw_advisories)} advisories...")

    # Create LLM
    try:
        llm = _create_llm()
    except Exception as e:
        errors.append(f"Failed to create LLM: {str(e)}")
        return {
            "analyzed_vulnerabilities": [],
            "current_step": "analyzed",
            "messages": messages,
            "errors": errors
        }

    # Analyze each advisory
    for i, advisory in enumerate(raw_advisories):
        try:
            messages.append(f"Analyzing {i+1}/{len(raw_advisories)}: {advisory.get('advisory_id', 'Unknown')}")

            analysis = _analyze_single_advisory(llm, advisory)

            if analysis:
                # Match against inventory
                affected_inventory = _match_inventory(analysis, inventory)
                analysis["affected_inventory"] = affected_inventory

                analyzed.append(analysis)
                messages.append(f"  - Found {len(affected_inventory)} affected devices")
            else:
                errors.append(f"Failed to analyze {advisory.get('advisory_id')}")

        except Exception as e:
            errors.append(f"Error analyzing {advisory.get('advisory_id', 'Unknown')}: {str(e)}")

    messages.append(f"Completed analysis of {len(analyzed)} advisories")

    return {
        "analyzed_vulnerabilities": analyzed,
        "current_step": "analyzed",
        "messages": messages,
        "errors": errors
    }
