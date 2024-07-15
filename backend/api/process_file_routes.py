import asyncio
import os
from typing import Optional

from config import settings
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse
from schema.data_schema import AuthSchema, FileCategory, ProcessFileResponse
from services.filenaming import file_rename
from services.filesize_check import check_filesize
from services.named_entity_recognition import named_entity_recogniztion
from services.perform_ocr import process_OCR
from services.pre_processing import image_processing
from services.scan_file import clamav_scan, yara_scan
from services.scope_optimization import scope_opt
from services.validate_sanitize_file_uploads import sanitize_file_content
from utils.authentication_header import validate_token
from utils.log_function import logs, setup_logging
from utils.miscellaneous import create_tmp_file

router = APIRouter()


@router.put("/processFile", response_model=ProcessFileResponse)
async def process_file_public(
    auth_user: AuthSchema = Depends(validate_token),
    scope_filesize_check: bool = Query(
        False, description="Confirm filesize check (True/False)"
    ),
    scope_malware_scan: bool = Query(
        False, description="Perform malware scan (True/False)"
    ),
    scope_validation_sanitization: bool = Query(
        False, description="Perform validation and sanitization (True/False)"
    ),
    allowed_filetypes: Optional[str] = Query(
        None,
        description="Allowed file types (comma-separated, e.g.,pdf,jpeg,jfif,png)",
    ),
    file_category: FileCategory = Query(..., description="Select file category"),
    scope_image_preprocessing: bool = Query(
        False, description="Perform image preprocessing (True/False)"
    ),
    scope_optical_character_recognition: bool = Query(
        False, description="Perform optical character recognition (True/False)"
    ),
    scope_named_entity_recognition: bool = Query(
        False, description="Perform named entity recognition (True/False)"
    ),
    scope_optimization: bool = Query(
        False, description="Perform file optimization (True/False)"
    ),
    scope_renaming: bool = Query(
        False, description="Perform file renaming (True/False)"
    ),
    file: UploadFile = File(..., description="File to be processed"),
    loglevel: Optional[str] = Query(
        "Info", description="Logging level (Debug, Info, Warning, Error, Critical)"
    ),
    return_file: bool = Query(
        False, description="Return the processed file (True/False)"
    ),
):
    """
    Processes an uploaded file based on the specified parameters.
    *If pdf is sent for ocr processing make sure not to send large pdf sizes
    Args:
        scope_filesize_check (bool): Confirm filesize check.
        max_filesize (float): Maximum allowed filesize in MB.
        scope_malware_scan (bool): Perform malware scan.
        scope_validation_sanitization (bool): Perform validation and sanitization.
        allowed_filetypes (str): Allowed file types (comma-separated, e.g., pdf,jpeg,jfif,png).
        file_category (str): File category (e.g., invoice, payment reminder, other).
        scope_image_preprocessing (bool): Perform image preprocessing.
        scope_optical_character_recognition (bool): Perform optical character recognition.
        scope_named_entity_recognition (bool): Perform named entity recognition.
        scope_optimization (bool): Perform file optimization.
        scope_renaming (bool): Perform file renaming.
        file (UploadFile): File to be processed.
        loglevel (str): Logging level.
        return_file (bool): Return the processed file.
    """

    setup_logging(loglevel)  # Set up logging based on the specified log level

    try:
        file_bytes = await file.read()
        file_name = file.filename
        file_extension = file.filename.split(".")[-1].lower()
        response_data = {}

        """ Perform filesize check and malware scan before executing the other scopes
        """
        if scope_filesize_check:
            try:
                check_filesize(file_bytes, settings.max_file_size)
                response_data["filesize_check"] = "PASSED"
                logs("info", "File size check passed")
            except HTTPException:
                response_data["filesize_check"] = "FAILED"
                return response_data

        # Perform malware scan if enabled
        if scope_malware_scan:
            clamav_task = asyncio.to_thread(clamav_scan, file_bytes, file_extension)
            yara_task = asyncio.to_thread(yara_scan, file_bytes, file_extension)

            # Wait for both tasks to complete
            clamav_result, yara_result = await asyncio.gather(clamav_task, yara_task)
            clamav_status, clamav_details, clamav_error = clamav_result

            # Handle ClamAV scan results
            if clamav_status == 0:
                clamav_response = {"status": "PASSED"}
            elif clamav_status == 1:
                if loglevel == "Debug":
                    clamav_response = {"status": "FAILED", "logs": clamav_details}
                else:
                    clamav_response = {"status": "FAILED"}
            else:
                clamav_response = {"status": "FAILED", "details": clamav_error}

            # Handle YARA scan results
            if yara_result == "OK":
                yara_response = {"status": "PASSED"}
            else:
                if loglevel == "Debug":
                    if yara_result == False:
                        yara_logs = "YARA failed to scan file"
                    else:
                        yara_logs = f"Suspicious {', '.join([match.rule for match in yara_result])} found in file"
                else:
                    yara_logs = None

                yara_response = {"status": "FAILED", "logs": yara_logs}

            # Set malware scan results in response data
            response_data["malware_scan"] = {
                "clamav": clamav_response,
                "yara": yara_response,
            }
            if (
                response_data["malware_scan"]["yara"]["status"] != "PASSED"
                or response_data["malware_scan"]["clamav"]["status"] != "PASSED"
            ):
                return response_data

        # Perform sanitization and validation if enabled
        if scope_validation_sanitization:
            try:
                sanitized_file = await sanitize_file_content(file, allowed_filetypes)
                response_data = {
                    "validation_result": "PASSED",
                    "sanitize_result": "PASSED",
                }
            except HTTPException as e:
                # Check if the raised exception matches the expected HTTPException
                if e.status_code == status.HTTP_400_BAD_REQUEST and (
                    "MIME type mismatch" in e.detail
                    or "File type not allowed" in e.detail
                ):
                    logs("error", f"Caught expected HTTPException: {e.detail}")
                    response_data["validation_result"] = "FAILED"
                    return response_data
                elif (
                    e.status_code == status.HTTP_400_BAD_REQUEST
                    and "Image sanitization error" in e.detail
                ):
                    logs("error", f"Caught expected HTTPException: {e.detail}")
                    response_data["sanitize_result"] = "FAILED"
                    return response_data
                else:
                    logs("error", f"Unexpected HTTPException: {e.detail}")
                    raise e  # Re-raise any other HTTPException

        if return_file:
            file_to_be_processed = file_bytes
            # perform image processessing if enabled
            if scope_image_preprocessing:
                if scope_validation_sanitization:
                    file_to_be_processed = sanitized_file
                processed_image = image_processing(file_to_be_processed)
            # Perform ocr if enabled
            if scope_optical_character_recognition:
                if scope_image_preprocessing and processed_image is not False:
                    file_to_be_processed = processed_image
                else:
                    if (
                        scope_validation_sanitization
                        and not scope_image_preprocessing
                        or scope_validation_sanitization
                        and scope_image_preprocessing
                        and not processed_image
                    ):
                        file_to_be_processed = sanitized_file
                ocr_file = await process_OCR(
                    file_name=file_name,
                    file_extension=file_extension,
                    file_bytes=file_to_be_processed,
                )
                return FileResponse(
                    ocr_file,
                    media_type=file.content_type,
                    filename=f"processed_{file_name}",
                )
            # perform renaming if enabled
            if scope_renaming:
                new_file_path = file_rename(file_bytes, file_name)
                return FileResponse(
                    path=new_file_path, filename=os.path.basename(new_file_path)
                )
            if scope_named_entity_recognition:
                named_entity_recogniztion()
            if scope_optimization:
                scope_opt()
        return response_data

    except HTTPException as http_exception:
        logs("error", f"HTTP exception occurred for this file: {http_exception.detail}")
        raise http_exception
    except Exception as e:
        logs("critical", f"An unexpected error occurred: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred. Please try again later.",
        )
