from typing import Tuple, Optional
import asyncio

import cv2
from fastapi import HTTPException

import numpy as np

from api.process_file.processor import get_mime_type
from config import settings
from services.filenaming import file_rename
from services.perform_ocr import process_OCR
from services.pre_processing import image_processing
from services.sanitize_file_uploads import sanitize_file_content
from services.scan_file import clamav_scan, yara_scan
from services.scope_optimization import scope_opt
from services.validate_file import validate_file


async def scan_file(processed_file: bytes, file_name: str, file_extension: str) -> Tuple:
    clamav_task = asyncio.to_thread(clamav_scan, processed_file, file_extension)
    yara_task = asyncio.to_thread(yara_scan, file_name, processed_file, file_extension)
    return await asyncio.gather(clamav_task, yara_task)


async def process_optical_character_recognition(body: dict, file_name: str, file_extension: str, processed_file: bytes,
                                                loglevel: str) -> Tuple[Optional[str], bool]:
    contrast_image = processed_file if isinstance(processed_file, np.ndarray) else None
    result = await process_OCR(
        file_name=file_name,
        file_extension=file_extension,
        file_bytes=None if contrast_image else processed_file,
        contrast_image=contrast_image,
        draw_debug=loglevel == "DEBUG",
    )
    return result, False


async def check_filesize_action(body, processed_file, file_extension, file_name, is_ndarray):
    allowed_max_value = body.get("max_file_size", settings.max_file_size) * 1048576
    check_filesize(processed_file, allowed_max_value)
    return processed_file, None, is_ndarray


async def malware_scan_action(body, processed_file, file_extension, file_name, is_ndarray):
    await scan_file(processed_file, file_name, file_extension)
    return processed_file, None, is_ndarray


async def validation_action(body, processed_file, file_extension, file_name, is_ndarray):
    actual_file_type = get_mime_type(file_name)
    validate_file(file_extension, actual_file_type, allowed_filetypes=body.get("allowed_filetypes"))
    return processed_file, None, is_ndarray


async def sanitization_action(body, processed_file, file_extension, file_name, is_ndarray):
    processed_file = await sanitize_file_content(processed_file, file_extension)
    return processed_file, None, is_ndarray


async def image_preprocessing_action(body, processed_file, file_extension, file_name, is_ndarray):
    processed_file = image_processing(processed_file)
    is_ndarray = isinstance(processed_file, np.ndarray)
    return processed_file, None, is_ndarray


async def ocr_processing_action(body, processed_file, file_extension, file_name, is_ndarray):
    file_path, is_ndarray = await process_optical_character_recognition(
        body, file_name, file_extension, processed_file, body.get("loglevel", "INFO")
    )
    return processed_file, file_path, is_ndarray


async def named_entity_recognition_action(body, processed_file, file_extension, file_name, is_ndarray):
    return processed_file, None, is_ndarray


async def optimization_action(body, processed_file, file_extension, file_name, is_ndarray):
    processed_file = scope_opt(processed_file, file_extension, file_name)
    return processed_file, processed_file, is_ndarray


async def renaming_action(body, processed_file, file_extension, file_name, is_ndarray):
    processed_file = file_rename(processed_file, file_name, is_ndarray)
    return processed_file, processed_file, is_ndarray


def generate_response_file_path(processed_file, file_name: str, is_ndarray: bool) -> str:
    if is_ndarray:
        _, buffer = cv2.imencode(".png", processed_file)
        return create_tmp_file(buffer.tobytes(), f"processed_{file_name}")
    return create_tmp_file(processed_file, f"processed_{file_name}")


def check_filesize(file_bytes: bytes, max_file_size: int):
    if len(file_bytes) > max_file_size:
        raise HTTPException(
            status_code=413, detail="File size exceeds the maximum limit"
        )
    return True
