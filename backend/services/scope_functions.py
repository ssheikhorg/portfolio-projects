from fastapi import HTTPException
from utils.log_function import logs

async def check_filesize(file, document_id: str, max_file_size: int):
    if file.spool_max_size > max_file_size:
        logs("error", f"Document ID {document_id}: File size exceeds the maximum limit")
        raise HTTPException(status_code=413, detail="File size exceeds the maximum limit")

async def check_malware(file, document_id: str):
    # Implement malware scan (ClamAV and YARA Forge)
    logs("info", f"Document ID {document_id}: Performing malware scan")
    # If malware found, raise HTTPException
    pass

async def validate_and_sanitize(file, document_id: str):
    # Implement validation and sanitization
    logs("info", f"Document ID {document_id}: Validating and sanitizing file")
    # If validation fails, raise HTTPException
    pass

async def preprocess_image(file, document_id: str):
    # Implement image preprocessing (OpenCV)
    logs("info", f"Document ID {document_id}: Preprocessing image")
    # If preprocessing fails, raise HTTPException
    pass

async def perform_ocr(file, document_id: str):
    # Implement OCR (check if already OCR’ed, if yes, skip)
    logs("info", f"Document ID {document_id}: Performing OCR")
    # If OCR fails, raise HTTPException
    pass

async def optimize_file(file, document_id: str):
    # Implement optimization (postprocessing, reduce file size, add OCR if not already done)
    logs("info", f"Document ID {document_id}: Optimizing file")
    # If optimization fails, raise HTTPException
    pass

async def rename_file(file, document_id: str):
    # Implement file renaming
    logs("info", f"Document ID {document_id}: Renaming file")
    # If renaming fails, raise HTTPException
    pass