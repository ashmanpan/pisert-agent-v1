"""Main LangGraph workflow for PSIRT Analysis."""

from typing import Dict, Any, List, Optional
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from .state import PSIRTState, create_initial_state
from .nodes import (
    fetch_psirt_node,
    analyze_vulnerability_node,
    assess_risk_node,
    generate_document_node
)


def should_continue_to_analyze(state: PSIRTState) -> str:
    """Determine if we should continue to analysis."""
    raw_advisories = state.get("raw_advisories", [])
    errors = state.get("errors", [])

    if not raw_advisories:
        # Check if we have fatal errors
        if any("fatal" in e.lower() for e in errors):
            return "end"
        return "end"

    return "analyze"


def should_continue_to_risk(state: PSIRTState) -> str:
    """Determine if we should continue to risk assessment."""
    analyzed = state.get("analyzed_vulnerabilities", [])

    if not analyzed:
        return "end"

    return "assess_risk"


def should_continue_to_document(state: PSIRTState) -> str:
    """Determine if we should continue to document generation."""
    assessments = state.get("risk_assessments", [])

    if not assessments:
        return "end"

    return "generate_doc"


def create_psirt_graph() -> StateGraph:
    """
    Create the PSIRT Analysis LangGraph workflow.

    Flow:
    1. fetch - Gather PSIRT data from API and scraper
    2. analyze - Deep vulnerability analysis with Claude
    3. assess_risk - Risk assessment and prioritization
    4. generate_doc - Generate structured documents

    Returns:
        Compiled StateGraph ready for execution
    """
    # Create workflow
    workflow = StateGraph(PSIRTState)

    # Add nodes
    workflow.add_node("fetch", fetch_psirt_node)
    workflow.add_node("analyze", analyze_vulnerability_node)
    workflow.add_node("assess_risk", assess_risk_node)
    workflow.add_node("generate_doc", generate_document_node)

    # Set entry point
    workflow.set_entry_point("fetch")

    # Add conditional edges
    workflow.add_conditional_edges(
        "fetch",
        should_continue_to_analyze,
        {
            "analyze": "analyze",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "analyze",
        should_continue_to_risk,
        {
            "assess_risk": "assess_risk",
            "end": END
        }
    )

    workflow.add_conditional_edges(
        "assess_risk",
        should_continue_to_document,
        {
            "generate_doc": "generate_doc",
            "end": END
        }
    )

    # Final edge
    workflow.add_edge("generate_doc", END)

    return workflow


class PSIRTGraph:
    """
    High-level interface for the PSIRT Analysis workflow.

    Usage:
        graph = PSIRTGraph()

        # Run with inventory
        result = graph.run(device_inventory=[...])

        # Or run with specific products
        result = graph.run(products=["IOS XR", "IOS XE"])

        # Get documents
        documents = result["documents"]
    """

    def __init__(self, checkpointer: bool = True):
        """Initialize the PSIRT graph."""
        self.workflow = create_psirt_graph()

        if checkpointer:
            self.memory = MemorySaver()
            self.app = self.workflow.compile(checkpointer=self.memory)
        else:
            self.app = self.workflow.compile()

    def run(
        self,
        device_inventory: Optional[List[Dict[str, Any]]] = None,
        products: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> PSIRTState:
        """
        Run the PSIRT analysis workflow.

        Args:
            device_inventory: List of device inventory dictionaries
            products: List of product names to check
            config: Optional configuration for the run

        Returns:
            Final state with documents and results
        """
        # Initialize state
        initial_state = create_initial_state()

        if device_inventory:
            initial_state["device_inventory"] = device_inventory

        if products:
            initial_state["products_to_check"] = products

        # Run config
        run_config = config or {"configurable": {"thread_id": "psirt-analysis-1"}}

        # Execute workflow
        result = self.app.invoke(initial_state, run_config)

        return result

    async def arun(
        self,
        device_inventory: Optional[List[Dict[str, Any]]] = None,
        products: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> PSIRTState:
        """
        Async version of run.
        """
        initial_state = create_initial_state()

        if device_inventory:
            initial_state["device_inventory"] = device_inventory

        if products:
            initial_state["products_to_check"] = products

        run_config = config or {"configurable": {"thread_id": "psirt-analysis-1"}}

        result = await self.app.ainvoke(initial_state, run_config)

        return result

    def stream(
        self,
        device_inventory: Optional[List[Dict[str, Any]]] = None,
        products: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Stream the workflow execution for real-time updates.

        Yields:
            State updates from each node
        """
        initial_state = create_initial_state()

        if device_inventory:
            initial_state["device_inventory"] = device_inventory

        if products:
            initial_state["products_to_check"] = products

        run_config = config or {"configurable": {"thread_id": "psirt-analysis-1"}}

        for event in self.app.stream(initial_state, run_config):
            yield event

    def get_state(self, config: Dict[str, Any]) -> PSIRTState:
        """Get the current state for a thread."""
        return self.app.get_state(config)

    def get_graph_visualization(self) -> str:
        """Get Mermaid diagram of the graph."""
        return self.app.get_graph().draw_mermaid()


# Convenience function for quick analysis
def analyze_psirt(
    device_inventory: Optional[List[Dict[str, Any]]] = None,
    products: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Convenience function to run PSIRT analysis.

    Args:
        device_inventory: List of device dictionaries
        products: List of product names

    Returns:
        Analysis results including documents
    """
    graph = PSIRTGraph(checkpointer=False)
    return graph.run(device_inventory=device_inventory, products=products)
