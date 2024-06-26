import asyncio
from typing import Optional

from config import settings
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from schema.data_schema import (
    ClamavScanResult,
    FileCategory,
    MalwareScanResult,
    ProcessFileResponse,
    StringMatch,
    YaraMatchDetails,
    YaraScanResult,
)

# from services.perform_ocr import process_OCR
from services.scan_file import clamav_scan, yara_scan
from services.scope_functions import check_filesize
from services.validate_sanitize_file_uploads import sanitize_file_content
from utils.log_function import logs, setup_logging

router = APIRouter()


@router.put(
    "/processFile",
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
        file_bytes = await file.read()
        file_extension = file.filename.split(".")[-1].lower()
        response_data = ProcessFileResponse()
        if scope_filesize_check:
            try:
                check_filesize(file_bytes, settings.max_file_size)
                response_data.filesize_check = "OK"
                logs("info", "File size check passed")
            except HTTPException:
                response_data.filesize_check = "file size too big"
        if scope_malware_scan:
            clamav_task = asyncio.to_thread(clamav_scan, file_bytes, file_extension)
            yara_task = asyncio.to_thread(yara_scan, file_bytes, file_extension)

            # Wait for both tasks to complete
            clamav_result, yara_result = await asyncio.gather(clamav_task, yara_task)
            clamav_status, clamav_details, clamav_error = clamav_result
            if clamav_status == 0:
                clamav_response = ClamavScanResult(status="OK")
            else:
                clamav_response = ClamavScanResult(status="FAIL", details=clamav_error)

            if yara_result == "OK":
                yara_response = YaraScanResult(status="OK", details="No matches found")
            else:
                yara_response = YaraScanResult(
                    status="FAIL",
                    details=[
                        YaraMatchDetails(
                            rule=match.rule,
                            namespace=match.namespace,
                            tags=match.tags,
                            meta=match.meta,
                            strings=[
                                StringMatch(
                                    identifier=string_match.identifier,
                                    # is_xor=string_match.is_xor,
                                )
                                for string_match in match.strings
                            ],
                        )
                        for match in yara_result
                    ],
                )

            response_data.malware_scan = MalwareScanResult(
                clamav=clamav_response, yara=yara_response
            )
        # if scope_validation_sanitization:
        #     await sanitize_file_content(file)
        # if scope_optical_character_recognition:
        #     OCR_result = await process_OCR(file_bytes)
        #     processed_file_bytes = OCR_result.getvalue()
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
