import asyncio
from typing import Optional, Union

from config import settings
from fastapi import (
    APIRouter,
    File,
    FileResponse,
    HTTPException,
    Query,
    StreamingResponse,
    UploadFile,
    status,
)
from schema.data_schema import (
    ClamavScanResult,
    FileCategory,
    MalwareScanResult,
    ProcessFileResponse,
    YaraScanResult,
)
from services.perform_ocr import process_OCR
from services.scan_file import clamav_scan, yara_scan
from services.scope_functions import check_filesize
from services.validate_sanitize_file_uploads import sanitize_file_content
from utils.log_function import logs, setup_logging
from utils.miscellaneous import create_tmp_file

router = APIRouter()


@router.put(
    "/processFile",
    response_model=Union[ProcessFileResponse, FileResponse, StreamingResponse],
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
    file: UploadFile = File(..., description="Load file for operation"),
    loglevel: str = Query(
        ..., description="Loglevel (Debug, Info, Warning, Error, Critical)"
    ),
    return_file: bool = Query(..., description="Return processed file (true/false)"),
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
    setup_logging(loglevel)  # Set up logging based on the specified log level

    try:
        file_bytes = await file.read()
        file_extension = file.filename.split(".")[-1].lower()
        response_data = ProcessFileResponse()

        # Perform filesize check if enabled
        if scope_filesize_check:
            try:
                check_filesize(file_bytes, settings.max_file_size)
                response_data.filesize_check = "PASSED"
                logs("info", "File size check passed")
            except HTTPException:
                response_data.filesize_check = "FAILED"

        # Perform malware scan if enabled
        if scope_malware_scan:
            clamav_task = asyncio.to_thread(clamav_scan, file_bytes, file_extension)
            yara_task = asyncio.to_thread(yara_scan, file_bytes, file_extension)

            # Wait for both tasks to complete
            clamav_result, yara_result = await asyncio.gather(clamav_task, yara_task)
            clamav_status, clamav_details, clamav_error = clamav_result

            # Handle ClamAV scan results
            if clamav_status == 0:
                clamav_response = ClamavScanResult(status="PASSED")
            elif clamav_status == 1:
                if loglevel == "Debug":
                    clamav_response = ClamavScanResult(
                        status="FAILED", logs=clamav_details
                    )
                else:
                    clamav_response = ClamavScanResult(status="FAILED")
            else:
                clamav_response = ClamavScanResult(
                    status="FAILED", details=clamav_error
                )

            # Handle YARA scan results
            if yara_result == "OK":
                yara_response = YaraScanResult(status="PASSED")
            else:
                if loglevel == "Debug":
                    if yara_result == False:
                        yara_logs = "YARA failed to scan file"
                    else:
                        yara_logs = f"Suspicious {', '.join([match.rule for match in yara_result])} found in file"
                else:
                    yara_logs = None

                yara_response = YaraScanResult(status="FAILED", logs=yara_logs)

            # Set malware scan results in response data
            response_data.malware_scan = MalwareScanResult(
                clamav=clamav_response, yara=yara_response
            )

        # Perform sanitization and validation if enabled
        if scope_validation_sanitization:
            other_scope_values = True
            if scope_filesize_check or scope_malware_scan:
                if scope_filesize_check:
                    if response_data.filesize_check != "PASSED":
                        other_scope_values = False
                if scope_malware_scan:
                    if (
                        response_data.malware_scan["clamav"]["status"] != "PASSED"
                        or response_data.malware_scan["yara"]["status"] != "PASSED"
                    ):
                        other_scope_values = False
            if other_scope_values:
                sanitized_file = sanitize_file_content(file)
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
            other_scope_values = True
            if scope_filesize_check or scope_malware_scan:
                if scope_filesize_check:
                    if response_data.filesize_check != "PASSED":
                        other_scope_values = False
                if scope_malware_scan:
                    if (
                        response_data.malware_scan["clamav"]["status"] != "PASSED"
                        or response_data.malware_scan["yara"]["status"] != "PASSED"
                    ):
                        other_scope_values = False
            if other_scope_values:
                ocr_byte_file = process_OCR(file_bytes)
                return StreamingResponse(
                    ocr_byte_file,
                    media_type="application/octet-stream",
                    headers={
                        "Content-Disposition": f"attachment; filename={file.filename}"
                    },
                )

        return response_data

    except HTTPException as http_exception:
        logs(
            "error",
            f"HTTP exception occurred for this file: {http_exception.detail}",
        )
        raise http_exception
    except Exception as e:
        logs(
            "critical",
            f"An unexpected error occurred in process_file for File : {str(e)}",
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred. Please try again later.",
        )
