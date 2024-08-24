from fastapi import HTTPException
from utils.log_function import logs


def check_filesize(file_bytes: bytes, max_file_size: int):
    if len(file_bytes) > max_file_size:
        logs("error", f"File size exceeds the maximum limit")
        raise HTTPException(
            status_code=700, detail="File size exceeds the maximum limit"
        )
    return True
