from fastapi import APIRouter, Depends, status, UploadFile, Query
from typing import Optional
from  ..models.data_models import FileCategory
from ..Authenticate_token import authorize_token
from  src.Redis_db import get_next_document_id,store_or_update_document,check_file_claim_ids
from ..Storing_and_Scheduling import store_file_in_redis
from  ..utils.Logging import logs
from ..Validate_Senitize import validate_file_content,sanitize_file_content

app = APIRouter()

@app.put("/processFile", dependencies=[Depends(authorize_token)])
async def process_file_public(
    claim_id: Optional[str] = Query(None, description="Optional claim ID"),
    sanitized_file: UploadFile = Depends(validate_file_content),
    file_category: FileCategory = Query(..., description="Select file category"),
    _: None = Depends(check_file_claim_ids)
):
    """
    This function processes a file upload request. It first validates and sanitizes the uploaded file,
    then stores or updates the document with priority in Redis. If the process is successful, it returns
    a response body with the status code, file ID, and claim ID. If an error occurs during the process,
    it logs the error and returns a 500 Internal Server Error response.
    """
    priority = False

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
        logs('info', f"Document {document_id} updated with priority")

        sanitized_file = await sanitize_file_content(sanitized_file)
        logs('info', f"File {sanitized_file.filename} sanitized")

        await store_file_in_redis(sanitized_file, document_id)
        logs('info', f"Sanitized file {sanitized_file.filename} stored in Redis with document ID: {document_id}")

        status_code = status.HTTP_200_OK
        file_id = document_id

    except Exception as e:
        logs('critical', "An error occurred in process_file", str(e))
        return {"status_code": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": "An error occurred"}

    response_body = {
        "status_code": status_code,
        "File_Id": file_id,
        "claim_id": claim_id
    }

    return response_body
