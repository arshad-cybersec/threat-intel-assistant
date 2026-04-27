from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    ANTHROPIC_API_KEY: str
    CLAUDE_MODEL: str = "claude-sonnet-4-6"
    MAX_TOKENS: int = 2048
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]

    class Config:
        env_file = ".env"


settings = Settings()
