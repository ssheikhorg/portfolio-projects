import asyncio
import os
import traceback
from typing import List, Optional

import cv2
import numpy as np
from config import settings
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from schema.data_schema import AuthSchema, FileCategory, ProcessFileResponse
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
from utils.log_function import logs, set_log_level
from utils.miscellaneous import create_tmp_file, get_mime_type

router = APIRouter()

LOG_LEVELS = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}


@router.put(
    "/processFile",
    responses={
        200: {"description": "Successful response"},
        400: {"description": "Bad Request"},
        413: {"description": "Payload Too Large"},
        415: {"description": "Unsupported Media Type"},
        422: {"description": "Unprocessable Entity"},
        500: {"description": "Internal Server Error"},
    },
)
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
        None, description="Allowed file types (comma-separated, e.g. pdf,jpeg,jfif,png)"
    ),
    file_category: FileCategory = Query(
        FileCategory.Unspecified.value, description="Select file category"
    ),
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
        True, description="Return the processed file (True) or JSON response (False)"
    ),
):
    log_messages = []

    loglevel = loglevel.upper()
    current_log_level = LOG_LEVELS.get(loglevel, 1)

    def log_collector(level, message):
        log_level = LOG_LEVELS.get(level.upper(), 0)
        if log_level == current_log_level:
            log_messages.append(f"{level.upper()}: {message}")
        logs(level, message)

    set_log_level(loglevel)

    try:
        file_bytes = await file.read()
        file_name = file.filename
        file_extension = file.filename.split(".")[-1].lower()

        log_collector("info", f"Processing file: {file_name}")
        log_collector(
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
            log_collector("info", "File size check passed")
            log_collector(
                "debug",
                f"File size: {len(processed_file)} bytes, Max allowed: {allowed_max_value} bytes",
            )

        if scope_malware_scan:
            log_collector("debug", "Starting malware scan")
            clamav_task = asyncio.to_thread(clamav_scan, processed_file, file_extension)
            yara_task = asyncio.to_thread(
                yara_scan, file_name, processed_file, file_extension
            )

            clamav_result, yara_result = await asyncio.gather(clamav_task, yara_task)
            clamav_status, clamav_details, clamav_error = clamav_result
            log_collector("info", "Malware scan completed")
            log_collector(
                "debug",
                f"ClamAV result - Status: {clamav_status}, Details: {clamav_details}, Error: {clamav_error}",
            )
            log_collector("debug", f"YARA result: {yara_result}")

        if scope_validation:
            log_collector("debug", "Starting file validation")
            actual_file_type = get_mime_type(file.file)
            validate_file(
                file_extension, actual_file_type, allowed_filetypes=allowed_filetypes
            )
            log_collector("info", "File validation passed")
            log_collector("debug", f"Actual file type: {actual_file_type}")

        if scope_sanitization:
            log_collector("debug", "Starting file sanitization")
            processed_file = await sanitize_file_content(file_bytes, file_extension)
            log_collector("info", "File sanitization completed")
            log_collector("debug", f"Sanitized file size: {len(processed_file)} bytes")

        if scope_image_preprocessing:
            log_collector("debug", "Starting image preprocessing")
            processed_file = image_processing(processed_file)
            is_ndarray = isinstance(processed_file, np.ndarray)
            log_collector("info", "Image preprocessing completed")
            log_collector(
                "debug",
                f"Preprocessed image type: {'numpy array' if is_ndarray else 'bytes'}",
            )

        if scope_optical_character_recognition:
            log_collector("debug", "Starting OCR processing")
            processed_file = await process_OCR(
                file_name=file_name,
                file_extension=file_extension,
                file_bytes=None if is_ndarray else processed_file,
                contrast_image=processed_file if is_ndarray else None,
                draw_debug=loglevel == "DEBUG",
            )
            is_ndarray = False
            file_path = processed_file
            log_collector("info", "OCR processing completed")
            log_collector("debug", f"OCR result file path: {file_path}")

        if scope_named_entity_recognition:
            log_collector("debug", "Starting named entity recognition")
            named_entity_recogniztion()
            log_collector("info", "Named entity recognition completed")

        if scope_optimization:
            log_collector("debug", "Starting file optimization")
            processed_file = scope_opt(processed_file, file_extension, file_name)
            file_path = processed_file
            log_collector("info", "File optimization completed")
            log_collector("debug", f"Optimized file path: {file_path}")

        if scope_renaming:
            log_collector("debug", "Starting file renaming")
            processed_file = file_rename(processed_file, file_name, is_ndarray)
            file_path = processed_file
            log_collector("info", "File renaming completed")
            log_collector("debug", f"Renamed file path: {file_path}")

        log_collector("debug", "Preparing response")
        if file_path:
            response_arg = file_path
        elif isinstance(processed_file, np.ndarray):
            _, buffer = cv2.imencode(".png", processed_file)
            tmp_file_path = create_tmp_file(buffer.tobytes(), f"processed_{file_name}")
            response_arg = tmp_file_path
        else:
            tmp_file_path = create_tmp_file(processed_file, f"processed_{file_name}")
            response_arg = tmp_file_path

        log_collector("info", "File processing completed successfully")
        log_collector("debug", f"Final response file path: {response_arg}")

        if return_file:
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
        else:
            return JSONResponse(
                content=ProcessFileResponse(
                    filename=os.path.basename(response_arg),
                    file_size=os.path.getsize(response_arg),
                    mime_type=file.content_type,
                    logs=log_messages,
                ).model_dump()
            )

    except HTTPException as http_exception:
        log_collector("error", f"HTTP exception occurred: {http_exception.detail}")
        log_collector(
            "debug", f"HTTP exception status code: {http_exception.status_code}"
        )
        raise http_exception
    except ValueError as ve:
        log_collector("error", f"Validation error: {str(ve)}")
        raise HTTPException(status_code=422, detail=str(ve))
    except IOError as io_error:
        log_collector("error", f"File operation error: {str(io_error)}")
        raise HTTPException(status_code=400, detail=str(io_error))
    except Exception as e:
        log_collector("critical", f"An unexpected error occurred: {str(e)}")
        log_collector(
            "debug",
            f"Exception type: {type(e).__name__}, Traceback: {traceback.format_exc()}",
        )
        raise HTTPException(
            status_code=500, detail=f"An unexpected error occurred: {str(e)}"
        )
