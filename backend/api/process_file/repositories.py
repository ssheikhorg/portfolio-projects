import os

from fastapi import UploadFile
from fastapi.responses import FileResponse, JSONResponse

from schema.data_schema import ProcessFileResponse
from utils.global_exception import handle_global_exception
from utils.log_function import get_logger
from .helpers import (
    check_filesize_action, malware_scan_action,
    validation_action, sanitization_action,
    image_preprocessing_action, ocr_processing_action,
    named_entity_recognition_action, optimization_action,
    renaming_action, generate_response_file_path
)

logger, memory_handler = get_logger("File Processing")


async def process_file_services(body: dict, file: UploadFile) -> JSONResponse | FileResponse:
    try:
        processed_file = await file.read()
        file_name = file.filename
        file_extension = file_name.split(".")[-1].lower()
        is_ndarray = False
        file_path = None

        # Pattern matching for different scopes
        for scope, action in {
            "scope_filesize_check": check_filesize_action,
            "scope_malware_scan": malware_scan_action,
            "scope_validation": validation_action,
            "scope_sanitization": sanitization_action,
            "scope_image_preprocessing": image_preprocessing_action,
            "scope_optical_character_recognition": ocr_processing_action,
            "scope_named_entity_recognition": named_entity_recognition_action,
            "scope_optimization": optimization_action,
            "scope_renaming": renaming_action,
        }.items():
            if body.get(scope, False):
                processed_file, file_path, is_ndarray = await action(
                    body, processed_file, file_extension, file_name, is_ndarray
                )

        # Generate response file path if needed
        response_arg = file_path or generate_response_file_path(processed_file, file_name, is_ndarray)

        # Prepare response
        if body.get("return_file", True):
            filename = os.path.basename(file_path) if body.get("scope_renaming", False) else f"processed_{file_name}"
            return FileResponse(
                response_arg,
                media_type=file.content_type,
                filename=filename,
            )
        else:
            return JSONResponse(
                content=ProcessFileResponse(
                    filename=os.path.basename(response_arg),
                    file_size=os.path.getsize(response_arg),
                    mime_type=file.content_type,
                    logs=memory_handler.log_storage,
                ).model_dump()
            )
    except Exception as e:
        handle_global_exception(e)
