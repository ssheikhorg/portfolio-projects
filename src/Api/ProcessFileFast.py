from fastapi import APIRouter, Depends, status, UploadFile, Query
from typing import Optional
from  ..models.data_models import FileCategory
from ..Authenticate_token import authenticate
from  src.Redis_db import get_next_document_id,store_or_update_document
from ..Storing_and_Scheduling import store_file_in_redis
from ..utils.Logging import logs
from ..Senitize import validate_file_content,sanitize_file_content

app = APIRouter()

@app.put("/processFileFast", dependencies=[Depends(authenticate)])
async def process_file(
    claim_id: Optional[str] = Query(None, description="Optional claim ID"),
    sanitized_file: UploadFile = Depends(validate_file_content),  # Validate file format and content
    file_category: FileCategory = Query(..., description="Select file category")
):
    """
    This function processes a file upload request. It first gets the next document ID, then stores or updates the document with priority.
    It then sanitizes the file and stores the sanitized file in Redis. If the process is successful, it returns a response body with the status code,
    file ID, and claim ID. If an error occurs during the process, it logs the error at the 'critical' level and returns a 500 Internal Server Error response.
    """
    try:
        document_id = await get_next_document_id()

        await store_or_update_document(
            document_id=document_id,
            claim_id=claim_id,
            file_id=document_id,
            file_category=file_category,
            log='Processing started',
            priority=True,
            ocr_result='No OCR result yet',
            ocr_file_path='Path to file'
        )

        sanitized_file = await sanitize_file_content(sanitized_file)

        await store_file_in_redis(sanitized_file, document_id)

        response_body = {
            "status_code": status.HTTP_200_OK,
            "File_Id": document_id,
            "claim_id": claim_id,
        }

        return response_body
    except Exception as e:
        logs('critical', "An error occurred in process_file", str(e))
        return {"status_code": status.HTTP_500_INTERNAL_SERVER_ERROR, "message": "An error occurred"}
