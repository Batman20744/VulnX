from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "VulnX"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = (
        "Intelligent Vulnerability Assessment "
        "and CVE Management Platform"
    )

    API_PREFIX: str = "/api/v1"

    DATABASE_URL: str = "sqlite:///./data/vulnx.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()