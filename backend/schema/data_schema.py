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
    scope_filesize_check: bool
    max_file_size: Optional[int]
    scope_malware_scan: bool
    scope_validation: bool
    scope_sanitization: bool
    file_category: FileCategory
    scope_image_preprocessing: bool
    scope_optical_character_recognition: bool
    scope_named_entity_recognition: bool
    scope_optimization: bool
    scope_renaming: bool
    return_file: bool
