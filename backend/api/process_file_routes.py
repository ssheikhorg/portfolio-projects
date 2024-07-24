import asyncio
import os
from typing import Optional

import cv2
import numpy as np
from config import settings
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from schema.data_schema import AuthSchema, FileCategory
from services.filenaming import file_rename
from services.filesize_check import check_filesize
from services.named_entity_recognition import named_entity_recogniztion
from services.perform_ocr import process_OCR
from services.pre_processing import image_processing
from services.sanitize_file_uploads import sanitize_file_content
from services.scan_file import clamav_scan, yara_scan
from services.scope_optimization import scope_opt
from services.validate_file import validate_file
from utils.authentication_header import validate_token
from utils.log_function import logs, setup_logging
from utils.miscellaneous import create_tmp_file, get_mime_type

router = APIRouter()


@router.put("/processFile", response_class=FileResponse)
async def process_file_public(
    # auth_user: AuthSchema = Depends(validate_token),
    scope_filesize_check: bool = Query(
        False, description="Confirm filesize check (True/False)"
    ),
    max_file_size: Optional[int] = Query(None, description="max file size in MB"),
    scope_malware_scan: bool = Query(
        False, description="Perform malware scan (True/False)"
    ),
    scope_validation: bool = Query(
        False, description="Perform validation (True/False)"
    ),
    scope_sanitization: bool = Query(
        False, description="perform sanitization(True/False)"
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

        # Process the file through each scope sequentially
        processed_file = file_bytes
        is_ndarray = False
        file_path = None

        if scope_filesize_check:
            try:
                allowed_max_value = (
                    max_file_size * 1048576 if max_file_size else settings.max_file_size
                )
                check_filesize(processed_file, allowed_max_value)
                logs("info", "File size check passed")
            except HTTPException:
                raise HTTPException(status_code=700, detail="File size check failed")

        if scope_malware_scan:
            clamav_task = asyncio.to_thread(clamav_scan, processed_file, file_extension)
            yara_task = asyncio.to_thread(yara_scan, processed_file, file_extension)

            clamav_result, yara_result = await asyncio.gather(clamav_task, yara_task)
            clamav_status, clamav_details, clamav_error = clamav_result
            if clamav_status != 0 or yara_result != "OK":
                raise HTTPException(status_code=700, detail="Malware scan failed")

        if scope_validation:
            try:
                actual_file_type = get_mime_type(file.file)
                validate_file(
                    file_extension,
                    actual_file_type,
                    allowed_filetypes=allowed_filetypes,
                )
            except HTTPException:
                raise HTTPException(status_code=700, detail="Validation Failed")

        if scope_sanitization:
            try:
                processed_file = await sanitize_file_content(file_bytes, file_extension)
            except HTTPException:
                raise HTTPException(status_code=700, detail="Sanitization failed")

        if scope_image_preprocessing:
            processed_file = image_processing(processed_file)
            if isinstance(processed_file, np.ndarray):
                is_ndarray = True

        if scope_optical_character_recognition:
            processed_file = await process_OCR(
                file_name=file_name,
                file_extension=file_extension,
                file_bytes=None if is_ndarray else processed_file,
                contrast_image=processed_file if is_ndarray else None,
            )
            is_ndarray = False
            file_path = processed_file

        if scope_named_entity_recognition:
            named_entity_recogniztion()

        if scope_optimization:
            processed_file = scope_opt(processed_file, file_extension, file_name)
            file_path = processed_file

        if scope_renaming:
            processed_file = file_rename(processed_file, file_name, is_ndarray)
            file_path = processed_file

        # Determine the appropriate argument for FileResponse
        if file_path:
            response_arg = file_path
        elif isinstance(processed_file, np.ndarray):
            # Convert numpy array to bytes
            _, buffer = cv2.imencode(".png", processed_file)
            tmp_file_path = create_tmp_file(buffer.tobytes(), f"processed_{file_name}")
            response_arg = tmp_file_path
        else:
            # For byte content
            tmp_file_path = create_tmp_file(processed_file, f"processed_{file_name}")
            response_arg = tmp_file_path

        # Return the processed file
        if scope_renaming:
            return FileResponse(
                response_arg,
                media_type=file.content_type,
                filename=os.path.basename(file_path),
            )
        else:
            return FileResponse(
                response_arg,
                media_type=file.content_type,
                filename=f"processed_{file_name}",
            )

    except HTTPException as http_exception:
        logs("error", f"HTTP exception occurred for this file: {http_exception.detail}")
        raise http_exception
    except Exception as e:
        logs("critical", f"An unexpected error occurred: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An internal server error occurred. Please try again later.",
        )
