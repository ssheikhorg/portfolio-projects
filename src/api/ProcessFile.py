from fastapi import APIRouter, Depends, status, UploadFile, Query, HTTPException
from typing import Optional
from ..models.data_models import FileCategory
from ..utils.process_files import get_next_document_id, store_or_update_document
from ..utils.save_file import store_file_in_redis
from ..utils.log_function import logs
from ..services.validate_sanitize_file_uploads import sanitize_file_content
from ..utils.authenticate_token import authorize_token
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a file handler and set its level to INFO
file_handler = logging.FileHandler('logfile.log')
file_handler.setLevel(logging.INFO)

# Create a formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Set the formatter for the file handler
file_handler.setFormatter(formatter)

# Add the file handler to the root logger
logging.getLogger().addHandler(file_handler)

app = APIRouter()

@app.put("/processFile", dependencies=[Depends(authorize_token)])
async def process_file_public(
    priority: bool = Query(..., description="Priority flag (true/false)"),
    claim_id: Optional[str] = Query(None, description="Optional claim ID"),
    sanitized_file: UploadFile = Depends(sanitize_file_content),
    file_category: FileCategory = Query(..., description="Select file category"),
    payload: dict = Depends(authorize_token)
):
    
    """
    Processes an uploaded file, stores it in Redis,
    and returns a response with the file ID and claim ID.

    """
    
        # Check if the endpoint name matches any of the endpoints in the aud claim of the payload
    if payload.get('aud'):
            aud_endpoints = payload['aud'].split(',')
            if any(endpoint.strip() == '/processFile' for endpoint in aud_endpoints):
                logs('critical', "Access restricted for endpoint in process_file_public")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Access restricted for this endpoint",
                    headers={"WWW-Authenticate": "Bearer"},
                )
    try:
        document_id = await get_next_document_id()
        logs('info', f"Next document ID: {document_id}")    

        await store_or_update_document(
            document_id=document_id,
            claim_id=claim_id,
            file_id=document_id,
            file_category=file_category,
            log='wait for Processing',
            priority=priority,
            ocr_result='No OCR result yet',
            ocr_file_path='Path to file'
        )
        logs('info', f"Document {document_id} updated with priority: {priority}")

        sanitized_file = await sanitize_file_content(sanitized_file)
        logs('info', f"File {sanitized_file.filename} sanitized")

        await store_file_in_redis(sanitized_file, document_id)
        logs('info', f"Sanitized file {sanitized_file.filename} stored in Redis with document ID: {document_id}")

        status_code = status.HTTP_200_OK
        file_id = document_id

    except Exception as e:
        logs('critical', "An error occurred in process_file", str(e))
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred")

    response_body = {
        "status_code": status_code,
        "File_Id": file_id,
        "claim_id": claim_id
    }

    return response_body
