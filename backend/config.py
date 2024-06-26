import json
from functools import lru_cache
from typing import Dict, List

from pydantic import validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    project_name: str = "FileAPI Processor"
    project_description: str = (
        "Sanitization and Validation, Malware Scanning, OCR and NER Processing, File Optimization"
    )
    redis_host: str
    redis_port: int
    redis_db: int
    secret_username: str
    secret_password: str
    bearer_token: str
    secret_key: str
    algorithm: str
    api_tokens: List[Dict[str, str]]
    expiration_time_minutes: int
    issuer: str
    clamav_config_file_path: str
    clamav_scanned_dir: str
    max_file_size: int
    yara_rule_packages: str = "/ziv/shared/packages/yara_rules.yar"

    @validator("api_tokens", pre=True)
    def parse_api_tokens(cls, value):
        if isinstance(value, str):
            return json.loads(value.replace("'", '"'))
        return value

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings():
    return Settings()


settings = get_settings()

""" DEBUG Confirm if settings have been properly loaded
"""
# print(settings)
