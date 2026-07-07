import os
from dataclasses import dataclass, field
from pathlib import Path

# Load .env from project root
_env_path = Path(__file__).resolve().parents[2] / ".env"
if _env_path.exists():
    try:
        from dotenv import load_dotenv

        load_dotenv(str(_env_path))
    except ImportError:
        pass


@dataclass
class LLMConfig:
    endpoint: str = field(
        default_factory=lambda: os.getenv(
            "AEGIS_LLM_ENDPOINT",
            "https://api.groq.com/openai/v1",
        )
    )
    api_key: str = field(
        default_factory=lambda: os.getenv("AEGIS_LLM_API_KEY", "")
    )
    model: str = field(
        default_factory=lambda: os.getenv(
            "AEGIS_LLM_MODEL", "llama-3.3-70b-versatile"
        )
    )
    timeout: int = 30
    max_retries: int = 2

    @property
    def configured(self) -> bool:
        return bool(self.api_key) and "your_api_key" not in self.api_key
