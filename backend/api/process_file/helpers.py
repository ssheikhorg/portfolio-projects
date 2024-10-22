from typing import Tuple, Optional
import asyncio

import cv2
from fastapi import HTTPException

import numpy as np

from services.filenaming import file_rename
from services.perform_ocr import process_OCR
from services.pre_processing import image_processing
from services.sanitize_file_uploads import sanitize_file_content
from services.scope_optimization import scope_opt
from config import settings
from .processor import create_tmp_file


async def process_optical_character_recognition(file_name: str, file_extension: str, processed_file: bytes) -> str:
    contrast_image = processed_file if isinstance(processed_file, np.ndarray) else None
    result = await process_OCR(
        file_name=file_name,
        file_extension=file_extension,
        file_bytes=None if isinstance(processed_file, np.ndarray) else processed_file,
        contrast_image=contrast_image,
    )
    return result


def generate_response_file_path(processed_file, file_name: str, is_ndarray: bool) -> str:
    if is_ndarray:
        _, buffer = cv2.imencode(".png", processed_file)
        return create_tmp_file(buffer.tobytes(), f"processed_{file_name}")
    return create_tmp_file(processed_file, f"processed_{file_name}")


def validate_file(file_extension: str, actual_mime_type: str, allowed_filetypes: str = None) -> None:
    mime_map = {
        "pdf": "application/pdf",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "jfif": "image/jpeg",
        "pjpeg": "image/jpeg",
        "png": "image/png",
    }
    if allowed_filetypes:
        allowed_extensions = allowed_filetypes.split(",")
    else:
        allowed_extensions = settings.allowed_filetypes.split(",")

    if file_extension not in allowed_extensions:
        raise HTTPException(
            status_code=415,
            detail="File type not allowed",
        )

    expected_mime_type = mime_map.get(file_extension, "application/octet-stream")
    if actual_mime_type != expected_mime_type:
        raise HTTPException(
            status_code=415,
            detail="File type not allowed",
        )
    print("File type validated")