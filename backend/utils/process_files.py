from typing import Optional

import redis.asyncio as redis
from config import settings
from fastapi import HTTPException, Query, status
from utils.log_function import logs

REDIS_HOST = settings.redis_host
REDIS_PORT = settings.redis_port
REDIS_DB = settings.redis_db

# Create a redis connection pool
pool = redis.ConnectionPool(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)

# Create a redis client with the connection pool
redis_client = redis.Redis(connection_pool=pool)


async def get_next_document_id():
    """

    Get the next document ID from Redis.
    If no highest document ID is found, initialize it to 1.

    """
    try:
        highest_id = await redis_client.get("highest_document_id")
        if highest_id is None:
            document_id = 1
        else:
            document_id = int(highest_id.decode()) + 1
        await redis_client.set("highest_document_id", document_id)
        logs("info", f"Next document ID: {document_id}")
        return document_id
    except Exception as e:
        logs("critical", "An error occurred ", str(e))
        return None


async def store_or_update_document(
    document_id,
    claim_id,
    file_id,
    file_category,
    log,
    priority,
    ocr_result,
    ocr_file_path,
):
    """
    Store or update a document in Redis.
    """
    try:
        # Convert None to an empty string for storage
        claim_id = claim_id or ""

        await redis_client.hset(
            f"document:{document_id}",
            mapping={
                "claim_id": claim_id,
                "file_id": file_id,
                "file_category": file_category.value,
                "log": log,
                "priority": str(priority),
                "ocr_result": ocr_result,
                "ocr_file_path": ocr_file_path,
            },
        )

        if claim_id:
            await redis_client.set(f"claim_index:{claim_id}", document_id)
        if file_id:
            await redis_client.set(f"file_index:{file_id}", document_id)

        stored_document = await redis_client.hgetall(f"document:{document_id}")

        # Convert empty string back to None when retrieving
        stored_document = {
            k: (v if v != b"" else None) for k, v in stored_document.items()
        }

        logs("info", f"Document {document_id}: {stored_document}")
        return stored_document
    except Exception as e:
        logs("critical", f"An error occurred in store_or_update_document: {str(e)}")
        return None


async def check_file_claim_ids(
    claim_id: Optional[str] = Query(None, description="Claim ID")
):
    """
    Check if a claim ID is provided.
    If not, raise an HTTPException.
    """
    try:
        if not claim_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Please provide a claimID",
            )
        logs("info", f"Claim ID: {claim_id}")
        return claim_id
    except Exception as e:
        logs("critical", "An error occurred", str(e))
        return None
