from functools import lru_cache
from typing import Any, Dict, List
from pathlib import Path

from pydantic_settings import BaseSettings

ROOT_PATH = Path(__file__).resolve().parent


class Settings(BaseSettings):
    project_name: str = "FileAPI Processor"
    project_description: str = (
        "Sanitization and Validation, Malware Scanning, OCR and NER Processing, File Optimization"
    )
    clamav_config_file_path: str = ROOT_PATH / "config_files/clamd.conf"
    clamav_scanned_dir: str
    max_file_size: int
    yara_rule_packages: str = "/ziv/shared/packages/yara_rules.yar"
    secret_key: str
    algorithm: str
    api_tokens: List[Dict[str, Any]]
    expiration_time_minutes: int
    issuer: str
    cron_schedule: str
    allowed_filetypes: str

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings():
    return Settings()


settings = get_settings()
