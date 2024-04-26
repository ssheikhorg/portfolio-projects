import os
import redis.asyncio as redis
from fastapi import HTTPException, status, UploadFile, Query
from datetime import datetime, time
from typing import Optional
from dotenv import load_dotenv
from .Schedule_celery import process_file_task

env_path = "src/Variables.env"
load_dotenv(env_path)

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_DB = os.getenv("REDIS_DB")

# Create a redis connection pool
pool = redis.ConnectionPool(host="172.30.80.1", port=6379, db=0)

# Create a redis client with the connection pool
redis_client = redis.Redis(connection_pool=pool)

async def get_next_document_id():
    """
    Get the next document ID from Redis.
    If no highest document ID is found, initialize it to 1.
    """
    highest_id = await redis_client.get('highest_document_id')
    if highest_id is None:
        document_id = 1
    else:
        document_id = int(highest_id.decode()) + 1
    await redis_client.set('highest_document_id', document_id)
    return document_id

async def store_or_update_document(document_id, claim_id, file_id, file_category, log, priority, ocr_result, ocr_file_path):
    """
    Store or update a document in Redis.
    """
    
    await redis_client.hset(f'document:{document_id}', mapping={
        'claim_id': claim_id,
        'file_id': file_id,
        'file_category': file_category.value,
        'log': log,
        'priority': str(priority),
        'ocr_result': ocr_result,
        'ocr_file_path': ocr_file_path
    })

    if claim_id:
        await redis_client.set(f'claim_index:{claim_id}', document_id)
    if file_id:
        await redis_client.set(f'file_index:{file_id}', document_id)

    stored_document = await redis_client.hgetall(f'document:{document_id}')
    print(f"Document {document_id}: {stored_document}")

async def store_file_in_redis(file: UploadFile, document_id: int):
    """
    Store an uploaded file in Redis.
    """
    file_contents = await file.read()  
    await redis_client.set(f'file:{document_id}', file_contents)

    priority = True  
    if priority:
        process_file_task.apply_async(args=[document_id, priority])
    else:
        off_peak_time = datetime.combine(datetime.now().date(), time(22, 0))  # 10 PM
        process_file_task.apply_async(args=[document_id, priority], eta=off_peak_time)

async def check_file_claim_ids(claim_id: Optional[str] = Query(None, description="Claim ID")):
    """
    Check if a claim ID is provided.
    If not, raise an HTTPException.
    """
    if not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a claimID",
        )
