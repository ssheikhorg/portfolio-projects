from typing import Union

from fastapi import HTTPException
from pydantic import ValidationError
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.status import (
    HTTP_422_UNPROCESSABLE_ENTITY, HTTP_400_BAD_REQUEST,
    HTTP_500_INTERNAL_SERVER_ERROR
)


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
