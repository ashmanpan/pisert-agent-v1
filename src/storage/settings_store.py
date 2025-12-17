"""Settings storage for API keys and configuration."""

import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
import base64
import hashlib


@dataclass
class AppSettings:
    """Application settings including API keys."""
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    cisco_client_id: str = ""
    cisco_client_secret: str = ""
    default_llm_provider: str = "bedrock"  # "anthropic", "openai", or "bedrock"
    embedding_model: str = "all-MiniLM-L6-v2"
    # AWS Bedrock settings
    aws_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-sonnet-4-20250514-v1:0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def is_configured(self) -> bool:
        """Check if at least one LLM is configured."""
        # Bedrock uses IAM roles, so it's always "configured" when selected
        if self.default_llm_provider == "bedrock":
            return True
        return bool(self.anthropic_api_key or self.openai_api_key)

    def get_active_llm_config(self) -> Dict[str, Any]:
        """Get the active LLM provider configuration."""
        if self.default_llm_provider == "bedrock":
            return {
                "provider": "bedrock",
                "region": self.aws_region,
                "model_id": self.bedrock_model_id
            }
        elif self.default_llm_provider == "openai" and self.openai_api_key:
            return {"provider": "openai", "api_key": self.openai_api_key}
        elif self.anthropic_api_key:
            return {"provider": "anthropic", "api_key": self.anthropic_api_key}
        elif self.openai_api_key:
            return {"provider": "openai", "api_key": self.openai_api_key}
        return {"provider": None}

    def get_active_llm_key(self) -> tuple:
        """Get the active LLM provider and key (legacy support)."""
        config = self.get_active_llm_config()
        if config["provider"] == "bedrock":
            return ("bedrock", None)
        return (config.get("provider"), config.get("api_key"))


class SettingsStore:
    """Persistent settings storage with encryption."""

    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or Path("/app/data/settings.json")
        self._encryption_key = self._get_or_create_key()
        self._fernet = Fernet(self._encryption_key)
        self._settings: Optional[AppSettings] = None

    def _get_or_create_key(self) -> bytes:
        """Get or create encryption key."""
        key_path = self.storage_path.parent / ".encryption_key"
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            return key_path.read_bytes()

        key = Fernet.generate_key()
        key_path.write_bytes(key)
        os.chmod(key_path, 0o600)
        return key

    def _encrypt(self, value: str) -> str:
        """Encrypt a string value."""
        if not value:
            return ""
        return self._fernet.encrypt(value.encode()).decode()

    def _decrypt(self, value: str) -> str:
        """Decrypt a string value."""
        if not value:
            return ""
        try:
            return self._fernet.decrypt(value.encode()).decode()
        except Exception:
            return ""

    def load(self) -> AppSettings:
        """Load settings from storage."""
        if self._settings is not None:
            return self._settings

        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.storage_path.exists():
            self._settings = AppSettings()
            return self._settings

        try:
            data = json.loads(self.storage_path.read_text())

            self._settings = AppSettings(
                anthropic_api_key=self._decrypt(data.get("anthropic_api_key", "")),
                openai_api_key=self._decrypt(data.get("openai_api_key", "")),
                cisco_client_id=self._decrypt(data.get("cisco_client_id", "")),
                cisco_client_secret=self._decrypt(data.get("cisco_client_secret", "")),
                default_llm_provider=data.get("default_llm_provider", "bedrock"),
                embedding_model=data.get("embedding_model", "all-MiniLM-L6-v2"),
                aws_region=data.get("aws_region", "us-east-1"),
                bedrock_model_id=data.get("bedrock_model_id", "anthropic.claude-sonnet-4-20250514-v1:0")
            )
        except Exception:
            self._settings = AppSettings()

        return self._settings

    def save(self, settings: AppSettings) -> None:
        """Save settings to storage."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "anthropic_api_key": self._encrypt(settings.anthropic_api_key),
            "openai_api_key": self._encrypt(settings.openai_api_key),
            "cisco_client_id": self._encrypt(settings.cisco_client_id),
            "cisco_client_secret": self._encrypt(settings.cisco_client_secret),
            "default_llm_provider": settings.default_llm_provider,
            "embedding_model": settings.embedding_model,
            "aws_region": settings.aws_region,
            "bedrock_model_id": settings.bedrock_model_id
        }

        self.storage_path.write_text(json.dumps(data, indent=2))
        os.chmod(self.storage_path, 0o600)
        self._settings = settings

    def update(self, **kwargs) -> AppSettings:
        """Update specific settings."""
        settings = self.load()

        for key, value in kwargs.items():
            if hasattr(settings, key) and value is not None:
                setattr(settings, key, value)

        self.save(settings)
        return settings

    def clear(self) -> None:
        """Clear all settings."""
        self._settings = AppSettings()
        if self.storage_path.exists():
            self.storage_path.unlink()

    def mask_key(self, key: str) -> str:
        """Mask an API key for display."""
        if not key or len(key) < 12:
            return "Not configured"
        return f"{key[:8]}...{key[-4:]}"


# Global settings store
_settings_store: Optional[SettingsStore] = None


def get_settings_store() -> SettingsStore:
    """Get or create global settings store."""
    global _settings_store
    if _settings_store is None:
        _settings_store = SettingsStore()
    return _settings_store


def get_settings() -> AppSettings:
    """Get current settings."""
    return get_settings_store().load()
