from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from schema.data_schema import FileCategory
from services.process_files import store_or_update_document
from services.save_file import store_file_in_redis
from utils.authenticate_token import authorize_token
from utils.log_function import setup_logging, logs
from utils.validate_sanitize_file_uploads import sanitize_file_content
from utils.scope_checks import check_filesize, check_malware, validate_and_sanitize, preprocess_image, perform_ocr, optimize_file, rename_file
import os

router = APIRouter()

class ProcessFileResponse(BaseModel):
    status_code: int
    file_id: string
    
@router.put("/processFile", dependencies=[Depends(authorize_token)], response_model=ProcessFileResponse)
async def process_file_public(
    scope_filesize_check: bool = Query(..., description="Filesize check (true/false)"),
    scope_malware_scan: bool = Query(..., description="Malware scan (true/false)"),
    scope_validation_sanitization: bool = Query(..., description="Validation & Sanitization (true/false)"),
    scope_image_preprocessing: bool = Query(..., description="Image preprocessing (true/false)"),
    scope_optical_character_recognition: bool = Query(..., description="Optical character recognition (true/false)"),
    scope_named_entity_recognition: bool = Query(..., description="Named entity recognition (true/false)"),
    scope_optimization: bool = Query(..., description="File optimization (true/false)"),
    scope_renaming: bool = Query(..., description="File renaming (true/false)"),
    file_category: FileCategory = Query(..., description="Select file category"),
    file: UploadFile = Depends(sanitize_file_content),
    loglevel: str = Query(..., description="Loglevel (Debug, Info, Warning, Error, Critical)"),
):
    ''' Processes an uploaded file and returns a response based on parameters
    
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
    '''
    setup_logging(loglevel)

    try:
        await file_id = assign_file_id()
        max_file_size = int(os.getenv("MAX_FILE_SIZE", 2 * 1024 * 1024))  # Default to 2 MB if not set
        if scope_filesize_check:
            await check_filesize(file, file_id, max_file_size)
        if scope_malware_scan:
            await check_malware(file, file_id)
        if scope_validation_sanitization:
            await validate_and_sanitize(file, file_id)
        if scope_image_preprocessing:
            await preprocess_image(file, file_id)
        if scope_optical_character_recognition:
            await perform_ocr(file, file_id)
        if scope_optimization:
            await optimize_file(file, file_id)
        if scope_renaming:
            await rename_file(file, file_id)
        
        ''' Store or update document in database
        '''
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
        logs("info", f"Sanitized file {sanitized_file.filename} stored in Redis with document ID: {file_id}")

        response_body = ProcessFileResponse(
            status_code=status.HTTP_200_OK,
            file_id=file_id,
        )
        return response_body

    except HTTPException as http_exception:
        logs("error", f"HTTP exception occurred for Document ID {file_id}: {http_exception.detail}")
        raise http_exception
    except Exception as e:
        logs("critical", f"An unexpected error occurred in process_file for File ID {file_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred. Please try again later.",
        )
