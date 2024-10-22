import traceback
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.status import (
    HTTP_422_UNPROCESSABLE_ENTITY, HTTP_400_BAD_REQUEST,
    HTTP_500_INTERNAL_SERVER_ERROR
)

from .log_function import get_logger

logger, memory_handler = get_logger("File Processing")


def handle_global_exception(e: Exception) -> None:
    exception_map = {
        HTTPException: (e.status_code, e.detail) if isinstance(e, HTTPException) else (500, "Unknown HTTP Exception"),
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


async def request_validation_exception_handler(
        _: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        {
            "message": "Bad Request",
            "data": exc.errors(),
        },
        status_code=HTTP_400_BAD_REQUEST,
    )


async def type_error_exception_handler(_: Request, exc: TypeError) -> JSONResponse:
    return JSONResponse(
        {
            "message": "Type Error",
            "data": str(exc),
        },
        status_code=HTTP_422_UNPROCESSABLE_ENTITY,
    )


async def http_error_handler(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        {
            "message": "Something went wrong",
            "data": exc.detail,
        },
        status_code=exc.status_code,
    )


async def unicorn_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        {
            "message": "Something went wrong",
            "data": str(exc),
        },
        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
    )
