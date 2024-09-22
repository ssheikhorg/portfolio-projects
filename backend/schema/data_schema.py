from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class StringMatch(BaseModel):
    identifier: str


class YaraMatchDetails(BaseModel):
    rule: str
    namespace: str
    tags: List[str]
    meta: dict
    strings: List[StringMatch]


class YaraScanResult(BaseModel):
    status: str
    logs: Optional[str] = None


class ClamavScanResult(BaseModel):
    status: str
    logs: Optional[str] = None


class MalwareScanResult(BaseModel):
    clamav: ClamavScanResult
    yara: YaraScanResult


# Define an Enum for file categories
class FileCategory(str, Enum):
    Invoice = "Invoice"
    PaymentReminder = "PaymentReminder"
    Unspecified = "Unspecified"


class AuthSchema(BaseModel):
    subject: str
    issuer: str


class ServiceInfo(BaseModel):
    id: Optional[str]
    name: Optional[str]
    description: Optional[str]
    organization: Optional[str]
    contactUrl: Optional[str]
    documentationUrl: Optional[str]
    environment: Optional[str]
    version: Optional[str]

    class Config:
        from_attributes = True


service_info_response = {}


class ProcessFileResponse(BaseModel):
    filename: str
    file_size: int
    mime_type: str
    logs: List[str]


class FileProcessingOptions(BaseModel):
    scope_filesize_check: bool = Field(False, description="Confirm filesize check (True/False)")
    max_file_size: Optional[int] = Field(None, description="Max file size in MB")
    scope_malware_scan: bool = Field(False, description="Perform malware scan (True/False)")
    scope_validation: bool = Field(False, description="Perform validation (True/False)")
    scope_sanitization: bool = Field(False, description="Perform sanitization (True/False)")
    allowed_filetypes: Optional[str] = Field(
        None, description="Allowed file types (comma-separated, e.g. pdf,jpeg,jfif,png)"
    )
    file_category: FileCategory = Field(
        FileCategory.Unspecified, description="Select file category"
    )
    scope_image_preprocessing: bool = Field(
        False, description="Perform image preprocessing (True/False)"
    )
    scope_optical_character_recognition: bool = Field(
        False, description="Perform optical character recognition (True/False)"
    )
    scope_named_entity_recognition: bool = Field(
        False, description="Perform named entity recognition (True/False)"
    )
    scope_optimization: bool = Field(
        False, description="Perform file optimization (True/False)"
    )
    scope_renaming: bool = Field(
        False, description="Perform file renaming (True/False)"
    )
    loglevel: Optional[str] = Field(
        "Info", description="Logging level (Debug, Info, Warning, Error, Critical)"
    )
    return_file: bool = Field(
        True, description="Return the processed file (True) or JSON response (False)"
    )
