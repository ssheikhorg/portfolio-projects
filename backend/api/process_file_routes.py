import asyncio
from typing import Optional, Union

from config import settings
from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse
from schema.data_schema import ProcessFileResponse
from services.perform_ocr import process_OCR
from services.scan_file import clamav_scan, yara_scan
from services.scope_functions import check_filesize
from services.validate_sanitize_file_uploads import sanitize_file_content
from utils.log_function import logs, setup_logging
from utils.miscellaneous import create_tmp_file

router = APIRouter()


@router.put("/processFile", response_model=None)
async def process_file_public(
    scope_filesize_check: bool = Query(
        False, description="Confirm filesize check (True/False)"
    ),
    scope_malware_scan: bool = Query(
        False, description="Perform malware scan (True/False)"
    ),
    scope_validation_sanitization: bool = Query(
        False, description="Perform validation and sanitization (True/False)"
    ),
    scope_optical_character_recognition: bool = Query(
        False, description="Perform optical character recognition (True/False)"
    ),
    file: UploadFile = File(..., description="File to be processed"),
    loglevel: Optional[str] = Query(
        "Info", description="Logging level (Debug, Info, Warning, Error, Critical)"
    ),
    return_file: bool = Query(
        False, description="Return the processed file (True/False)"
    ),
) -> Union[ProcessFileResponse, FileResponse]:
    """
    Processes an uploaded file and returns a response based on parameters

    Args:
        scope_filesize_check (bool): Confirm filesize check.
        scope_malware_scan (bool): Perform malware scan.
        scope_validation_sanitization (bool): Perform validation and sanitization.
        scope_optical_character_recognition (bool): Perform optical character recognition.
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

        if return_file:
            # Perform sanitization and validation if enabled
            if scope_validation_sanitization:
                sanitized_file = await sanitize_file_content(file)
                sanitized_file_byte = await sanitized_file.read()
                temp_file_path = create_tmp_file(
                    sanitized_file_byte, sanitized_file.filename
                )
                return FileResponse(
                    temp_file_path,
                    media_type=sanitized_file.content_type,
                    filename=f"sanitized_{sanitized_file.filename}",
                )

            # Perform ocr if enabled
            if scope_optical_character_recognition:
                ocr_file = await process_OCR(file_bytes, file_name)
                ocr_file_byte = await ocr_file.read()
                temp_file_path = create_tmp_file(ocr_file_byte, ocr_file.filename)
                return FileResponse(
                    temp_file_path,
                    media_type=ocr_file.content_type,
                    filename=f"processed_{ocr_file.filename}",
                )

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
