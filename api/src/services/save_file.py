import os

import redis.asyncio as redis
from fastapi import UploadFile
from src.core.config import settings
from src.utils.log_function import logs

REDIS_HOST = settings.redis_host
REDIS_PORT = settings.redis_port
REDIS_DB = settings.redis_db


# Create a redis connection pool
pool = redis.ConnectionPool(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

# Create a redis client with the connection pool
redis_client = redis.Redis(connection_pool=pool)


async def store_file_in_redis(file: UploadFile, document_id: int):
    """
    Store an uploaded file in Redis.

    """
    try:
        file_contents = await file.read()
        await redis_client.set(f"file:{document_id}", file_contents)
        logs(
            "info",
            f"Stored file {file.filename} in Redis with document ID: {document_id}",
        )

    except Exception as e:
        logs("critical", "An error occurred", str(e))
