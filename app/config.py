from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "IMAP Code Resolver"
    environment: str = "dev"
    database_url: str = "sqlite:///./app.db"
    admin_token: str = "change-me-admin-token"
    admin_panel_password: str = "123456"

    key_hash_secret: str = "change-me-key-hash-secret"
    credential_encrypt_key: str = ""

    imap_server: str = "imap.gmail.com"
    imap_port: int = 993
    imap_fetch_window_minutes: int = 60
    rate_limit_minutes: int = 180
    cache_ttl_seconds: int = 30
    code_max_age_minutes: int = 60
    imap_max_messages_scan: int = 30
    poll_interval_seconds: int = 90

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
