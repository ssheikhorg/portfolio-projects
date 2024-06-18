import asyncio
from typing import Optional

from config import settings
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from schema.data_schema import FileCategory, ProcessFileResponse
from services.scan_file import clamav_scan, yara_scan
from services.validate_sanitize_file_uploads import sanitize_file_content
from utils.authenticate_token import authorize_token
from utils.log_function import logs, setup_logging
from utils.miscellaneous import generate_file_id
from utils.process_files import get_next_document_id, store_or_update_document
from utils.save_file import store_file_in_redis

router = APIRouter()


@router.put(
    "/processFile",
    dependencies=[Depends(authorize_token)],
    response_model=ProcessFileResponse,
)
async def process_file_public(
    scope_filesize_check: bool = Query(..., description="Filesize check (true/false)"),
    scope_malware_scan: bool = Query(..., description="Malware scan (true/false)"),
    scope_validation_sanitization: bool = Query(
        ..., description="Validation & Sanitization (true/false)"
    ),
    scope_image_preprocessing: bool = Query(
        ..., description="Image preprocessing (true/false)"
    ),
    scope_optical_character_recognition: bool = Query(
        ..., description="Optical character recognition (true/false)"
    ),
    scope_named_entity_recognition: bool = Query(
        ..., description="Named entity recognition (true/false)"
    ),
    scope_optimization: bool = Query(..., description="File optimization (true/false)"),
    scope_renaming: bool = Query(..., description="File renaming (true/false)"),
    file_category: FileCategory = Query(..., description="Select file category"),
    file: UploadFile = File(..., description="load file for operation"),
    loglevel: str = Query(
        ..., description="Loglevel (Debug, Info, Warning, Error, Critical)"
    ),
):
    """Processes an uploaded file and returns a response based on parameters

    Args:
        scope_filesize_check (bool): Filesize check (true/false).
        scope_malware_scan (bool): Malware scan (true/false).
        scope_validation_sanitization (bool): Validation & Sanitization (true/false).
        scope_image_preprocessing (bool): Image preprocessing (true/false).
        scope_optical_character_recognition (bool): Optical character recognition (true/false).
        scope_named_entity_recognition (bool): Named entity recognition (true/false).
        scope_optimization (bool): File optimization (true/false).
        scope_renaming (bool): File renaming (true/false).
        file_category (FileCategory): Select file category.
        file (UploadFile): File to be processed (pdf, jpeg, jfif, png).
        loglevel (str): Loglevel (Debug, Info, Warning, Error, Critical).

    Returns:
        ProcessFileResponse: Contains status code and file id
    """
    setup_logging(loglevel)

    try:
        file_id = generate_file_id()
        max_file_size = settings.max_file_size

        if scope_malware_scan:
            clamav_task = clamav_scan(file)
            yara_task = yara_scan(file)

            # Wait for both tasks to complete
            clamav_result, yara_result = await asyncio.gather(clamav_task, yara_task)

        """ Store or update document in database
        """
        await store_or_update_document(
            file_id=file_id,
            file_category=file_category,
            log="wait for Processing",
            ocr_result="No OCR result yet",
            ocr_file_path="Path to file",
        )
        logs("info", f"Document {file_id} updated with file category: {file_category}")

        sanitized_file = await sanitize_file_content(file)
        logs("info", f"File {sanitized_file.filename} sanitized")

        await store_file_in_redis(sanitized_file, file_id)
        logs(
            "info",
            f"Sanitized file {sanitized_file.filename} stored in Redis with document ID: {file_id}",
        )

        response_body = ProcessFileResponse(
            status_code=status.HTTP_200_OK,
            file_id=file_id,
        )
        return response_body

    except HTTPException as http_exception:
        logs(
            "error",
            f"HTTP exception occurred for Document ID {file_id}: {http_exception.detail}",
        )
        raise http_exception
    except Exception as e:
        logs(
            "critical",
            f"An unexpected error occurred in process_file for File ID {file_id}: {str(e)}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred. Please try again later.",
        )
