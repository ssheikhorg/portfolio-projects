from config import settings
from fastapi import HTTPException, status
from utils.log_function import logs


def validate_mime_type(actual_mime_type: str, expected_mime_type: str):
    """
    Validates MIME type of file against expected formats using content sniffing.
    Raises HTTPException for unsupported or mismatched formats.
    """
    if actual_mime_type != expected_mime_type:
        logs(
            "warning",
            f"MIME type mismatch: expected {expected_mime_type}, got {actual_mime_type}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"MIME type mismatch: expected {expected_mime_type}, got {actual_mime_type}.",
        )
    logs("info", f"MIME type validated based on content: {actual_mime_type}")


def validate_file(
    file_extension: str, actual_mime_type: str, allowed_filetypes: str = None
):
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
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File type not allowed",
        )

    expected_mime_type = mime_map.get(file_extension, "application/octet-stream")
    validate_mime_type(actual_mime_type, expected_mime_type)
