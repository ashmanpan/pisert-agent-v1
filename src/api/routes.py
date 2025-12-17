"""API routes for PSIRT agent."""

import asyncio
from typing import Optional, List
from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.responses import JSONResponse
import tempfile
import os

from .schemas import (
    QueryRequest, QueryResponse, SourceInfo,
    AnalysisRequest, AnalysisResponse, AnalysisStatusResponse,
    AdvisoryResponse, AdvisoryListResponse,
    InventoryItem, InventoryResponse,
    CVEQueryRequest, ProductQueryRequest,
    StatisticsResponse, HealthResponse, ErrorResponse,
    RiskAssessmentInfo, MitigationInfo
)
from ..rag.qa_chain import PSIRTQAChain, get_qa_chain
from ..storage.qdrant_store import QdrantStore, get_qdrant_store
from ..ingestion.excel_parser import ExcelInventoryParser
from ..agents.graph import PSIRTGraph
from ..config import settings


router = APIRouter()

# Global state for analysis
_analysis_status = {
    "running": False,
    "status": "idle",
    "current_step": "",
    "messages": [],
    "errors": [],
    "documents_generated": 0,
    "advisories_processed": 0
}
_current_inventory = []


# ============== Health & Status ==============

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Check API health status."""
    qdrant_ok = False
    try:
        store = get_qdrant_store()
        store.client.get_collections()
        qdrant_ok = True
    except Exception:
        pass

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        qdrant_connected=qdrant_ok,
        llm_configured=bool(settings.anthropic_api_key)
    )


@router.get("/status", response_model=AnalysisStatusResponse)
async def get_analysis_status():
    """Get current analysis status."""
    return AnalysisStatusResponse(**_analysis_status)


# ============== Query Endpoints ==============

@router.post("/query", response_model=QueryResponse)
async def query_psirt(request: QueryRequest):
    """
    Query the PSIRT knowledge base.

    Ask questions about security advisories and get AI-powered answers
    with source citations.
    """
    try:
        qa_chain = get_qa_chain()

        response = qa_chain.query(
            question=request.question,
            limit=request.limit,
            severity_filter=request.severity_filter.value if request.severity_filter else None,
            min_risk_score=request.min_risk_score
        )

        sources = [
            SourceInfo(
                advisory_id=s["advisory_id"],
                title=s["title"],
                severity=s["severity"],
                risk_score=s["risk_score"],
                similarity_score=s["similarity_score"],
                url=s.get("url")
            )
            for s in response.sources
        ]

        return QueryResponse(
            answer=response.answer,
            sources=sources,
            query=response.query,
            confidence=response.confidence
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/query/cve", response_model=QueryResponse)
async def query_by_cve(request: CVEQueryRequest):
    """Query information about a specific CVE."""
    try:
        qa_chain = get_qa_chain()
        response = qa_chain.query_about_cve(request.cve_id)

        sources = [
            SourceInfo(
                advisory_id=s["advisory_id"],
                title=s["title"],
                severity=s["severity"],
                risk_score=s["risk_score"],
                similarity_score=s["similarity_score"],
                url=s.get("url")
            )
            for s in response.sources
        ]

        return QueryResponse(
            answer=response.answer,
            sources=sources,
            query=response.query,
            confidence=response.confidence
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/query/product", response_model=QueryResponse)
async def query_by_product(request: ProductQueryRequest):
    """Query vulnerabilities affecting a specific product."""
    try:
        qa_chain = get_qa_chain()
        response = qa_chain.query_about_product(
            product=request.product,
            severity=request.severity.value if request.severity else None
        )

        sources = [
            SourceInfo(
                advisory_id=s["advisory_id"],
                title=s["title"],
                severity=s["severity"],
                risk_score=s["risk_score"],
                similarity_score=s["similarity_score"],
                url=s.get("url")
            )
            for s in response.sources
        ]

        return QueryResponse(
            answer=response.answer,
            sources=sources,
            query=response.query,
            confidence=response.confidence
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============== Inventory Endpoints ==============

@router.post("/upload", response_model=InventoryResponse)
async def upload_inventory(file: UploadFile = File(...)):
    """
    Upload an Excel inventory file.

    Parses the Excel file and stores the device inventory for
    vulnerability matching.
    """
    global _current_inventory

    if not file.filename.endswith(('.xlsx', '.xls')):
        raise HTTPException(status_code=400, detail="File must be an Excel file (.xlsx or .xls)")

    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        # Parse the Excel file
        parser = ExcelInventoryParser(tmp_path)
        devices = parser.get_device_inventory()

        # Convert to list of dicts
        _current_inventory = [d.to_dict() for d in devices]

        # Get unique products
        products = list(set(d.router_type for d in devices if d.router_type))

        # Cleanup
        os.unlink(tmp_path)

        return InventoryResponse(
            items=[
                InventoryItem(
                    serial_no=d.serial_no,
                    network_layer=d.network_layer,
                    node=d.node,
                    router_type=d.router_type,
                    current_version=d.current_version,
                    image_version=d.image_version
                )
                for d in devices
            ],
            total=len(devices),
            products=products
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/inventory", response_model=InventoryResponse)
async def get_inventory():
    """Get the current device inventory."""
    global _current_inventory

    products = list(set(d.get("router_type", "") for d in _current_inventory if d.get("router_type")))

    return InventoryResponse(
        items=[
            InventoryItem(
                serial_no=d.get("serial_no", 0),
                network_layer=d.get("network_layer", ""),
                node=d.get("node", ""),
                router_type=d.get("router_type", ""),
                current_version=d.get("current_version", ""),
                image_version=d.get("image_version", "")
            )
            for d in _current_inventory
        ],
        total=len(_current_inventory),
        products=products
    )


# ============== Analysis Endpoints ==============

async def run_analysis_background(products: List[str], inventory: List[dict]):
    """Run analysis in background."""
    global _analysis_status

    _analysis_status["running"] = True
    _analysis_status["status"] = "running"
    _analysis_status["messages"] = []
    _analysis_status["errors"] = []

    try:
        graph = PSIRTGraph(checkpointer=False)

        # Run analysis
        _analysis_status["current_step"] = "Initializing..."

        result = graph.run(
            device_inventory=inventory,
            products=products
        )

        # Update status
        _analysis_status["messages"] = result.get("messages", [])
        _analysis_status["errors"] = result.get("errors", [])
        _analysis_status["documents_generated"] = len(result.get("documents", []))
        _analysis_status["advisories_processed"] = len(result.get("raw_advisories", []))
        _analysis_status["current_step"] = result.get("current_step", "completed")

        # Store documents in Qdrant
        if result.get("documents"):
            _analysis_status["current_step"] = "Storing documents..."
            store = get_qdrant_store()
            store.add_documents(result["documents"])

        _analysis_status["status"] = "completed"

    except Exception as e:
        _analysis_status["status"] = "failed"
        _analysis_status["errors"].append(str(e))

    finally:
        _analysis_status["running"] = False


@router.post("/analyze", response_model=AnalysisResponse)
async def start_analysis(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks
):
    """
    Start PSIRT analysis.

    Fetches advisories, analyzes vulnerabilities, and stores
    documents in the vector database.
    """
    global _analysis_status, _current_inventory

    if _analysis_status["running"]:
        raise HTTPException(status_code=409, detail="Analysis already in progress")

    # Determine products
    products = request.products or []
    if not products and _current_inventory:
        products = list(set(d.get("router_type", "") for d in _current_inventory if d.get("router_type")))

    if not products:
        products = ["IOS XR", "IOS XE", "ASR", "NCS"]

    # Start background analysis
    background_tasks.add_task(run_analysis_background, products, _current_inventory)

    return AnalysisResponse(
        status="started",
        documents_count=0,
        advisories_analyzed=0,
        critical_count=0,
        high_count=0,
        affected_devices=0,
        messages=["Analysis started in background"],
        errors=[]
    )


# ============== Advisory Endpoints ==============

@router.get("/advisories", response_model=AdvisoryListResponse)
async def list_advisories(
    page: int = 1,
    limit: int = 20,
    severity: Optional[str] = None
):
    """List all stored advisories."""
    try:
        store = get_qdrant_store()
        offset = (page - 1) * limit

        advisories_data = store.get_all_advisories(
            limit=limit,
            offset=offset,
            severity=severity
        )

        advisories = []
        for a in advisories_data:
            advisories.append(AdvisoryResponse(
                id=a.get("id", ""),
                advisory_id=a.get("advisory_id", ""),
                title=a.get("title", ""),
                cve_ids=a.get("cve_ids", []),
                severity=a.get("severity", "Unknown"),
                risk_score=a.get("risk_score", 0),
                priority_level=a.get("priority_level", ""),
                created_at=a.get("created_at")
            ))

        stats = store.get_statistics()
        total = stats.get("total_documents", len(advisories))

        return AdvisoryListResponse(
            advisories=advisories,
            total=total,
            page=page,
            limit=limit
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/advisories/{advisory_id}", response_model=AdvisoryResponse)
async def get_advisory(advisory_id: str):
    """Get a specific advisory by ID."""
    try:
        store = get_qdrant_store()
        doc = store.get_by_advisory_id(advisory_id)

        if not doc:
            raise HTTPException(status_code=404, detail="Advisory not found")

        analysis = doc.get("analysis", {})
        risk = doc.get("risk_assessment", {})
        mitigation = doc.get("mitigation", {})

        return AdvisoryResponse(
            id=doc.get("id", ""),
            advisory_id=doc.get("advisory_id", ""),
            title=doc.get("title", ""),
            cve_ids=doc.get("cve_ids", []),
            severity=risk.get("severity", "Unknown"),
            risk_score=risk.get("composite_risk_score", 0),
            priority_level=risk.get("priority_level", ""),
            when_is_this_a_problem=analysis.get("when_is_this_a_problem"),
            clear_conditions=analysis.get("clear_conditions", []),
            affected_products=analysis.get("affected_products", []),
            risk_assessment=RiskAssessmentInfo(
                severity=risk.get("severity", "Unknown"),
                cvss_score=risk.get("cvss_score"),
                exploitability=risk.get("exploitability", "Unknown"),
                impact_description=risk.get("impact_description", ""),
                composite_risk_score=risk.get("composite_risk_score", 0),
                priority_level=risk.get("priority_level", "")
            ) if risk else None,
            mitigation=MitigationInfo(
                recommended_actions=mitigation.get("recommended_actions", []),
                patches_available=mitigation.get("patches_available", False),
                workarounds=mitigation.get("workarounds", []),
                upgrade_path=mitigation.get("upgrade_path", ""),
                estimated_effort=mitigation.get("estimated_effort", "Unknown")
            ) if mitigation else None,
            affected_inventory=doc.get("affected_inventory", []),
            created_at=doc.get("created_at"),
            url=doc.get("metadata", {}).get("url")
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/advisories/{advisory_id}")
async def delete_advisory(advisory_id: str):
    """Delete an advisory."""
    try:
        store = get_qdrant_store()
        success = store.delete_advisory(advisory_id)

        if not success:
            raise HTTPException(status_code=404, detail="Advisory not found")

        return {"message": f"Advisory {advisory_id} deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============== Statistics Endpoints ==============

@router.get("/statistics", response_model=StatisticsResponse)
async def get_statistics():
    """Get database statistics."""
    try:
        store = get_qdrant_store()
        stats = store.get_statistics()

        return StatisticsResponse(
            total_documents=stats.get("total_documents", 0),
            severity_distribution=stats.get("severity_distribution", {}),
            collection_status=str(stats.get("collection_status", "unknown"))
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
