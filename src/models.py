from enum import Enum
from typing import Optional
from pydantic import BaseModel
from fastapi import Query, UploadFile

class FileCategory(str, Enum):
    Invoice = "Invoice"
    PaymentReminder = "PaymentReminder"
    Other = "Other"

class ProcessFileRequest(BaseModel):
    claim_id: Optional[str] = Query(None, description="Optional claim ID")
    file_category: FileCategory
    file: UploadFile
