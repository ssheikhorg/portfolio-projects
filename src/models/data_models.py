from enum import Enum

# Define an Enum for file categories
class FileCategory(str, Enum):
    Invoice = "Invoice"
    PaymentReminder = "PaymentReminder"
    Other = "Other"

