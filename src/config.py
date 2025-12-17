"""Configuration settings for PSIRT Security Analysis Agent."""

import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Anthropic API
    anthropic_api_key: str = Field(default="", env="ANTHROPIC_API_KEY")

    # Cisco OpenVuln API
    cisco_client_id: str = Field(default="", env="CISCO_CLIENT_ID")
    cisco_client_secret: str = Field(default="", env="CISCO_CLIENT_SECRET")
    cisco_api_base_url: str = "https://apix.cisco.com/security/advisories/v2"
    cisco_token_url: str = "https://id.cisco.com/oauth2/default/v1/token"

    # Qdrant
    qdrant_host: str = Field(default="localhost", env="QDRANT_HOST")
    qdrant_port: int = Field(default=6333, env="QDRANT_PORT")
    qdrant_collection: str = Field(default="psirt_advisories", env="QDRANT_COLLECTION")

    # Application
    app_host: str = Field(default="0.0.0.0", env="APP_HOST")
    app_port: int = Field(default=8000, env="APP_PORT")
    debug: bool = Field(default=False, env="DEBUG")

    # Embedding
    embedding_model: str = Field(default="all-MiniLM-L6-v2", env="EMBEDDING_MODEL")

    # Paths
    base_dir: Path = Path(__file__).parent.parent
    data_dir: Path = base_dir / "data"
    uploads_dir: Path = data_dir / "uploads"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


# Global settings instance
settings = Settings()

# Ensure directories exist
settings.data_dir.mkdir(exist_ok=True)
settings.uploads_dir.mkdir(exist_ok=True)
