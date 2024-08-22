from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel


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
    filesize_check: Optional[str] = None
    malware_scan: Optional[MalwareScanResult] = None
    validation_result: Optional[str] = None
    sanitize_result: Optional[str] = None
