from pydantic import validator
from pydantic_settings import BaseSettings


# Get config values from env variables, see https://fastapi.tiangolo.com/advanced/settings/
# TODO: use lru_cache decorator
class Settings(BaseSettings):
    project_name: str = "illora"
    project_description: str = "this is a an api for file processing"
    redis_host: str = "172.30.80.1"
    redis_port: int = 6379
    redis_db: int = 0
    celery_broker_url: str = "redis://172.30.80.1:6379/1"
    secret_username: str = "webapp"
    secret_password: str = "ocrapp"
    bearer_token: str = "TOKEN"
    secret_key: str = "jwt123"
    algorithm: str = "HS256"
    api_tokens: str = (
        "[{'api_key': '6ba7b8109dad11d180b400c04fd430c8', 'subject': 'First TOKEN'},{'api_key': '3a2b4c6d8e0f1a2b3c4d5e6f7a8b9c0d', 'subject': 'Second TOKEN'}]"
    )
    expiration_time_minutes: int = 60
    issuer: str = "OCRAPP"
    clamav_config_file_path = "/app/clamd.conf"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

# print(settings)
