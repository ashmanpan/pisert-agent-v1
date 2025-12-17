"""Admin API routes for settings management."""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from ..storage.settings_store import get_settings_store, get_settings, AppSettings


admin_router = APIRouter(prefix="/admin", tags=["Admin"])


class SettingsUpdateRequest(BaseModel):
    """Request model for updating settings."""
    anthropic_api_key: Optional[str] = Field(default=None, description="Anthropic API key")
    openai_api_key: Optional[str] = Field(default=None, description="OpenAI API key")
    cisco_client_id: Optional[str] = Field(default=None, description="Cisco client ID")
    cisco_client_secret: Optional[str] = Field(default=None, description="Cisco client secret")
    default_llm_provider: Optional[str] = Field(default=None, description="Default LLM provider (anthropic, openai, or bedrock)")
    aws_region: Optional[str] = Field(default=None, description="AWS region for Bedrock")
    bedrock_model_id: Optional[str] = Field(default=None, description="Bedrock model ID")


class SettingsResponse(BaseModel):
    """Response model for settings."""
    anthropic_api_key: str
    openai_api_key: str
    cisco_client_id: str
    cisco_client_secret: str
    default_llm_provider: str
    embedding_model: str
    aws_region: str
    bedrock_model_id: str
    is_configured: bool


class TestKeyRequest(BaseModel):
    """Request to test an API key."""
    provider: str = Field(..., description="Provider: 'anthropic', 'openai', or 'bedrock'")
    api_key: Optional[str] = Field(default=None, description="API key to test (not needed for bedrock)")


class TestKeyResponse(BaseModel):
    """Response from key test."""
    success: bool
    message: str


@admin_router.get("/settings", response_model=SettingsResponse)
async def get_admin_settings():
    """Get current settings (API keys are masked)."""
    store = get_settings_store()
    settings = store.load()

    return SettingsResponse(
        anthropic_api_key=store.mask_key(settings.anthropic_api_key),
        openai_api_key=store.mask_key(settings.openai_api_key),
        cisco_client_id=store.mask_key(settings.cisco_client_id),
        cisco_client_secret=store.mask_key(settings.cisco_client_secret),
        default_llm_provider=settings.default_llm_provider,
        embedding_model=settings.embedding_model,
        aws_region=settings.aws_region,
        bedrock_model_id=settings.bedrock_model_id,
        is_configured=settings.is_configured()
    )


@admin_router.post("/settings", response_model=SettingsResponse)
async def update_admin_settings(request: SettingsUpdateRequest):
    """Update settings."""
    store = get_settings_store()

    # Build update dict, excluding None values
    updates = {}
    if request.anthropic_api_key is not None:
        updates["anthropic_api_key"] = request.anthropic_api_key
    if request.openai_api_key is not None:
        updates["openai_api_key"] = request.openai_api_key
    if request.cisco_client_id is not None:
        updates["cisco_client_id"] = request.cisco_client_id
    if request.cisco_client_secret is not None:
        updates["cisco_client_secret"] = request.cisco_client_secret
    if request.default_llm_provider is not None:
        if request.default_llm_provider not in ["anthropic", "openai", "bedrock"]:
            raise HTTPException(status_code=400, detail="Invalid LLM provider")
        updates["default_llm_provider"] = request.default_llm_provider
    if request.aws_region is not None:
        updates["aws_region"] = request.aws_region
    if request.bedrock_model_id is not None:
        updates["bedrock_model_id"] = request.bedrock_model_id

    settings = store.update(**updates)

    return SettingsResponse(
        anthropic_api_key=store.mask_key(settings.anthropic_api_key),
        openai_api_key=store.mask_key(settings.openai_api_key),
        cisco_client_id=store.mask_key(settings.cisco_client_id),
        cisco_client_secret=store.mask_key(settings.cisco_client_secret),
        default_llm_provider=settings.default_llm_provider,
        embedding_model=settings.embedding_model,
        aws_region=settings.aws_region,
        bedrock_model_id=settings.bedrock_model_id,
        is_configured=settings.is_configured()
    )


@admin_router.post("/test-key", response_model=TestKeyResponse)
async def test_api_key(request: TestKeyRequest):
    """Test an API key or Bedrock connection."""
    try:
        if request.provider == "bedrock":
            from langchain_aws import ChatBedrock
            import boto3

            settings = get_settings()
            bedrock_client = boto3.client(
                "bedrock-runtime",
                region_name=settings.aws_region
            )

            llm = ChatBedrock(
                client=bedrock_client,
                model_id=settings.bedrock_model_id,
                model_kwargs={"max_tokens": 10}
            )
            response = llm.invoke("Say 'OK'")
            return TestKeyResponse(success=True, message=f"Bedrock connection valid ({settings.bedrock_model_id})")

        elif request.provider == "anthropic":
            from langchain_anthropic import ChatAnthropic

            llm = ChatAnthropic(
                model="claude-sonnet-4-20250514",
                anthropic_api_key=request.api_key,
                max_tokens=10
            )
            response = llm.invoke("Say 'OK'")
            return TestKeyResponse(success=True, message="Anthropic API key is valid")

        elif request.provider == "openai":
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model="gpt-4o-mini",
                openai_api_key=request.api_key,
                max_tokens=10
            )
            response = llm.invoke("Say 'OK'")
            return TestKeyResponse(success=True, message="OpenAI API key is valid")

        else:
            raise HTTPException(status_code=400, detail="Invalid provider")

    except Exception as e:
        return TestKeyResponse(success=False, message=f"Connection test failed: {str(e)}")


@admin_router.delete("/settings")
async def clear_settings():
    """Clear all settings."""
    store = get_settings_store()
    store.clear()
    return {"message": "Settings cleared"}


@admin_router.get("/status")
async def get_system_status():
    """Get system status including service connectivity."""
    store = get_settings_store()
    settings = store.load()

    status = {
        "llm_configured": settings.is_configured(),
        "default_provider": settings.default_llm_provider,
        "anthropic_configured": bool(settings.anthropic_api_key),
        "openai_configured": bool(settings.openai_api_key),
        "bedrock_configured": settings.default_llm_provider == "bedrock",
        "aws_region": settings.aws_region,
        "bedrock_model_id": settings.bedrock_model_id,
        "cisco_configured": bool(settings.cisco_client_id and settings.cisco_client_secret),
        "qdrant_connected": False,
        "embedding_model": settings.embedding_model
    }

    # Test Qdrant connection
    try:
        from ..storage.qdrant_store import get_qdrant_store
        qdrant = get_qdrant_store()
        qdrant.client.get_collections()
        status["qdrant_connected"] = True
    except Exception:
        pass

    return status
