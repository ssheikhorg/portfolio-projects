from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    project_name: str = "FileAPI Processor"
    project_description: str = (
        "Sanitization and Validation, Malware Scanning, OCR and NER Processing, File Optimization"
    )
    clamav_config_file_path: str
    clamav_scanned_dir: str
    max_file_size: int
    yara_rule_packages: str = "/ziv/shared/packages/yara_rules.yar"

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
