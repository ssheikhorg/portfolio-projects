import os
import numpy as np
import yara
import magic

from fastapi import UploadFile, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from schema.data_schema import ProcessFileResponse
from utils.log_function import get_logger
from config import settings
from services.filenaming import file_rename
from services.pre_processing import image_processing
from services.sanitize_file_uploads import sanitize_file_content
from services.scan_file import mycallback
from services.scope_optimization import scope_opt
from utils.error_handler import handle_global_exception
from .helpers import (
    generate_response_file_path, process_optical_character_recognition, validate_file
)
from .processor import create_tmp_file

logger, memory_handler = get_logger("File Processing")


async def process_file_services(body: dict, file: UploadFile) -> JSONResponse | FileResponse:
    try:
        processed_file = await file.read()
        # scope_filesize_check
        allowed_max_value = body.get("max_file_size", settings.max_file_size) * 1048576
        if len(processed_file) > allowed_max_value:
            raise HTTPException(
                status_code=413, detail="File size exceeds the maximum limit"
            )

        file_name = file.filename
        file_extension = file_name.split(".")[-1].lower()
        is_ndarray = False
        file_path = generate_response_file_path(processed_file, file_name, is_ndarray)
        if not file_path:
            raise HTTPException(status_code=500, detail="An unexpected error occurred")

        # malware_scan
        file_path = os.path.join(settings.clamav_scanned_dir, f"file_to_scan.{file_extension}")
        with open(file_path, "wb") as f:
            f.write(processed_file)

        file_path = create_tmp_file(processed_file, f"file_to_scan.{file_extension}")
        externals = {
            "filename": file_name,
            "filepath": file_path,
            "extension": file_extension,
            "filetype": "",
            "md5": "",
            "filesize": os.path.getsize(file_path),
            "fullpath": os.path.abspath(file_path),
        }
        rules = yara.compile(filepath=settings.yara_rule_packages, externals=externals)
        matches = rules.match(
            file_path,
            callback=mycallback,
            which_callbacks=yara.CALLBACK_MATCHES,
        )
        if not matches:
            logger.info("File does not contain malware")

        # validation_action
        actual_file_type = magic.Magic(mime=True).from_buffer(processed_file)
        validate_file(file_extension, actual_file_type, body.get("allowed_filetypes"))
        # sanitization_action
        processed_file = await sanitize_file_content(processed_file, file_extension)
        # image_preprocessing_action
        processed_file = image_processing(processed_file)
        is_ndarray = isinstance(processed_file, np.ndarray)
        # ocr_processing_action
        file_path = await process_optical_character_recognition(file_name, file_extension, processed_file)
        # optimization_action
        processed_file = scope_opt(processed_file, file_extension, file_name)
        # renaming_action
        file_rename(processed_file, file_name, is_ndarray)

        # Prepare response
        if body.get("return_file", True):
            filename = os.path.basename(file_path) if body.get("scope_renaming", False) else f"processed_{file_name}"
            return FileResponse(
                file_path,
                media_type=file.content_type,
                filename=filename,
            )
        else:
            return JSONResponse(
                content=ProcessFileResponse(
                    filename=os.path.basename(file_path),
                    file_size=os.path.getsize(file_path),
                    mime_type=file.content_type,
                    logs=memory_handler.log_storage,
                ).model_dump()
            )
    except Exception as e:
        handle_global_exception(e)
