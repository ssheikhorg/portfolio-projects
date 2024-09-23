from fastapi import HTTPException
import traceback

from utils.log_function import get_logger

logger, memory_handler = get_logger("File Processing")


def handle_global_exception(e: Exception) -> None:
    exception_map = {
        HTTPException: (e.status_code, e.detail),  # type: ignore
        ValueError: (422, str(e)),
        IOError: (400, str(e)),
    }
    status_code, detail = exception_map.get(type(e), (500, f"An unexpected error occurred: {str(e)}"))  # type: ignore
    if isinstance(e, HTTPException):
        logger.error(f"HTTP exception occurred: {detail}")
        logger.debug(f"HTTP exception status code: {status_code}")
    else:
        severity_level = "error" if status_code < 500 else "critical"
        log_function = getattr(logger, severity_level)
        log_function(detail)
        logger.debug(f"Exception type: {type(e).__name__}, Traceback: {traceback.format_exc()}")

    raise HTTPException(status_code=status_code, detail=detail)
