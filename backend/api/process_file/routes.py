from typing import Optional

from fastapi import APIRouter, File, UploadFile, Form, Depends
from fastapi.responses import JSONResponse
from schema.data_schema import FileProcessingOptions, AuthSchema
from utils.authentication_header import validate_token
from .repositories import process_file_services

router = APIRouter(prefix="/file_service", tags=["File Processing"])


@router.put("/processFile")
async def process_file_public(
        _: AuthSchema = Depends(validate_token),
        file: UploadFile = File(..., description="File to be processed"),
        scope_filesize_check: bool = Form(..., description="Confirm filesize check (True/False)"),
        max_file_size: Optional[int] = Form(None, description="Max file size in MB"),
        scope_malware_scan: bool = Form(..., description="Perform malware scan (True/False)"),
        scope_validation: bool = Form(..., description="Perform validation (True/False)"),
        scope_sanitization: bool = Form(..., description="Perform sanitization (True/False)"),
        allowed_filetypes: Optional[str] = Form(None, description="Allowed file types"),
        file_category: str = Form(..., description="Select file category"),
        scope_image_preprocessing: bool = Form(..., description="Perform image preprocessing (True/False)"),
        scope_optical_character_recognition: bool = Form(..., description="Perform optical character recognition (True/False)"),
        scope_named_entity_recognition: bool = Form(..., description="Perform named entity recognition (True/False)"),
        scope_optimization: bool = Form(..., description="Perform file optimization (True/False)"),
        scope_renaming: bool = Form(..., description="Perform file renaming (True/False)"),
        return_file: bool = Form(..., description="Return file (True/False)"),
) -> JSONResponse:
    body = FileProcessingOptions(
        scope_filesize_check=scope_filesize_check,
        max_file_size=max_file_size,
        scope_malware_scan=scope_malware_scan,
        scope_validation=scope_validation,
        scope_sanitization=scope_sanitization,
        allowed_filetypes=allowed_filetypes,
        file_category=file_category,
        scope_image_preprocessing=scope_image_preprocessing,
        scope_optical_character_recognition=scope_optical_character_recognition,
        scope_named_entity_recognition=scope_named_entity_recognition,
        scope_optimization=scope_optimization,
        scope_renaming=scope_renaming,
        return_file=return_file
    )
    return await process_file_services(body.model_dump(), file)
