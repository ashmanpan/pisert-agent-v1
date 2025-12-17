"""Main FastAPI application for PSIRT Security Analysis Agent."""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import uvicorn

from .api.routes import router
from .api.admin_routes import admin_router
from .config import settings
from .storage.qdrant_store import get_qdrant_store


# Create FastAPI app
app = FastAPI(
    title="PSIRT Security Analysis Agent",
    description="""
    AI-powered security analysis agent for Cisco PSIRT advisories.

    Features:
    - Fetch and analyze Cisco security advisories
    - AI-powered vulnerability analysis using Claude/OpenAI
    - Risk assessment and prioritization
    - RAG-based Q&A for security queries
    - Device inventory matching

    ## Interfaces
    - **Admin UI**: /admin - Configure API keys and settings
    - **User UI**: /user - Ask security questions
    - **Full Dashboard**: / - Complete management interface

    ## Quick Start
    1. Go to /admin and configure your API keys
    2. Upload your device inventory (Excel file)
    3. Run analysis to fetch and process advisories
    4. Query the knowledge base for security information
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api", tags=["PSIRT API"])
app.include_router(admin_router, prefix="/api", tags=["Admin"])

# Static files
static_path = Path(__file__).parent.parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup."""
    try:
        # Initialize Qdrant collection
        store = get_qdrant_store()
        store.initialize_collection()
        print("Qdrant collection initialized")
    except Exception as e:
        print(f"Warning: Could not initialize Qdrant: {e}")
        print("Make sure Qdrant is running or start it with Docker")


@app.get("/", response_class=FileResponse)
async def root():
    """Serve the main web interface (full dashboard)."""
    index_path = static_path / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "PSIRT Security Analysis Agent API", "docs": "/docs"}


@app.get("/admin", response_class=FileResponse)
async def admin_ui():
    """Serve the Admin UI for API key management."""
    admin_path = static_path / "admin.html"
    if admin_path.exists():
        return FileResponse(str(admin_path))
    return HTMLResponse("<h1>Admin UI not found</h1>")


@app.get("/user", response_class=FileResponse)
async def user_ui():
    """Serve the User UI for asking questions."""
    user_path = static_path / "user.html"
    if user_path.exists():
        return FileResponse(str(user_path))
    return HTMLResponse("<h1>User UI not found</h1>")


@app.get("/api")
async def api_root():
    """API root endpoint."""
    return {
        "name": "PSIRT Security Analysis Agent",
        "version": "1.0.0",
        "interfaces": {
            "admin_ui": "/admin",
            "user_ui": "/user",
            "full_dashboard": "/"
        },
        "endpoints": {
            "health": "/api/health",
            "query": "/api/query",
            "upload": "/api/upload",
            "analyze": "/api/analyze",
            "advisories": "/api/advisories",
            "statistics": "/api/statistics",
            "admin_settings": "/api/admin/settings"
        }
    }


def main():
    """Run the application."""
    uvicorn.run(
        "src.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.debug
    )


if __name__ == "__main__":
    main()
