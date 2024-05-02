import os
import redis.asyncio as redis
from fastapi import UploadFile
from datetime import datetime, time
from dotenv import load_dotenv
from .Schedule_celery import process_file_task
from src.utils.Logging import logs

env_path = "src/Variables.env"
load_dotenv(env_path)

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_DB = os.getenv("REDIS_DB")

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
        await redis_client.set(f'file:{document_id}', file_contents)
        logs('info', f"Stored file {file.filename} in Redis with document ID: {document_id}")

        priority = True  
        if priority:
            process_file_task.apply_async(args=[document_id, priority])
            logs('info', f"Processing task for document ID: {document_id} with priority")
        else:
            off_peak_time = datetime.combine(datetime.now().date(), time(22, 0))  # 10 PM
            process_file_task.apply_async(args=[document_id, priority], eta=off_peak_time)
            logs('info', f"Processing task for document ID: {document_id} scheduled for off-peak time")
    except Exception as e:
        logs('critical', "An error occurred", str(e))
