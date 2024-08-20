import asyncio
import os
import traceback
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
    auth_user: AuthSchema = Depends(validate_token),
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
        description="Allowed file types (comma-separated, e.g. pdf,jpeg,jfif,png)",
    ),
    # file_category: FileCategory = Query(..., description="Select file category"),
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
        allowed_filetypes (str): Allowed file types (comma-separated, e.g. pdf,jpeg,jfif,png).
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

        logs("info", f"Processing file: {file_name}")
        logs(
            "debug",
            f"File details - Name: {file_name}, Extension: {file_extension}, Size: {len(file_bytes)} bytes",
        )

        processed_file = file_bytes
        is_ndarray = False
        file_path = None

        if scope_filesize_check:
            allowed_max_value = (
                max_file_size * 1048576 if max_file_size else settings.max_file_size
            )
            check_filesize(processed_file, allowed_max_value)
            logs("info", "File size check passed")
            logs(
                "debug",
                f"File size: {len(processed_file)} bytes, Max allowed: {allowed_max_value} bytes",
            )

        if scope_malware_scan:
            logs("debug", "Starting malware scan")
            clamav_task = asyncio.to_thread(clamav_scan, processed_file, file_extension)
            yara_task = asyncio.to_thread(yara_scan, processed_file, file_extension)

            clamav_result, yara_result = await asyncio.gather(clamav_task, yara_task)
            clamav_status, clamav_details, clamav_error = clamav_result
            logs("info", "Malware scan completed")
            logs(
                "debug",
                f"ClamAV result - Status: {clamav_status}, Details: {clamav_details}, Error: {clamav_error}",
            )
            logs("debug", f"YARA result: {yara_result}")

        if scope_validation:
            logs("debug", "Starting file validation")
            actual_file_type = get_mime_type(file.file)
            validate_file(
                file_extension, actual_file_type, allowed_filetypes=allowed_filetypes
            )
            logs("info", "File validation passed")
            logs("debug", f"Actual file type: {actual_file_type}")

        if scope_sanitization:
            logs("debug", "Starting file sanitization")
            processed_file = await sanitize_file_content(file_bytes, file_extension)
            logs("info", "File sanitization completed")
            logs("debug", f"Sanitized file size: {len(processed_file)} bytes")

        if scope_image_preprocessing:
            logs("debug", "Starting image preprocessing")
            processed_file = image_processing(processed_file)
            is_ndarray = isinstance(processed_file, np.ndarray)
            logs("info", "Image preprocessing completed")
            logs(
                "debug",
                f"Preprocessed image type: {'numpy array' if is_ndarray else 'bytes'}",
            )

        if scope_optical_character_recognition:
            logs("debug", "Starting OCR processing")
            processed_file = await process_OCR(
                file_name=file_name,
                file_extension=file_extension,
                file_bytes=None if is_ndarray else processed_file,
                contrast_image=processed_file if is_ndarray else None,
                draw_debug=loglevel == "Debug",
            )
            is_ndarray = False
            file_path = processed_file
            logs("info", "OCR processing completed")
            logs("debug", f"OCR result file path: {file_path}")

        if scope_named_entity_recognition:
            logs("debug", "Starting named entity recognition")
            named_entity_recogniztion()
            logs("info", "Named entity recognition completed")

        if scope_optimization:
            logs("debug", "Starting file optimization")
            processed_file = scope_opt(processed_file, file_extension, file_name)
            file_path = processed_file
            logs("info", "File optimization completed")
            logs("debug", f"Optimized file path: {file_path}")

        if scope_renaming:
            logs("debug", "Starting file renaming")
            processed_file = file_rename(processed_file, file_name, is_ndarray)
            file_path = processed_file
            logs("info", "File renaming completed")
            logs("debug", f"Renamed file path: {file_path}")

        logs("debug", "Preparing file response")
        if file_path:
            response_arg = file_path
        elif isinstance(processed_file, np.ndarray):
            _, buffer = cv2.imencode(".png", processed_file)
            tmp_file_path = create_tmp_file(buffer.tobytes(), f"processed_{file_name}")
            response_arg = tmp_file_path
        else:
            tmp_file_path = create_tmp_file(processed_file, f"processed_{file_name}")
            response_arg = tmp_file_path

        logs("info", "File processing completed successfully")
        logs("debug", f"Final response file path: {response_arg}")

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
        logs("error", f"HTTP exception occurred: {http_exception.detail}")
        logs("debug", f"HTTP exception status code: {http_exception.status_code}")
        raise http_exception
    except Exception as e:
        logs("critical", f"An unexpected error occurred: {str(e)}")
        logs(
            "debug",
            f"Exception type: {type(e).__name__}, Traceback: {traceback.format_exc()}",
        )
        raise HTTPException(
            status_code=500,
            detail="An internal server error occurred. Please try again later.",
        )
