from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel


# Define an Enum for file categories
class FileCategory(str, Enum):
    Invoice = "Invoice"
    PaymentReminder = "PaymentReminder"
    Other = "Other"


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
