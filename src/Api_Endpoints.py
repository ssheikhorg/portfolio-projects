from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Query
from typing import Optional
from .models import FileCategory
from .Authenticate_token import authenticate,authorize_token
from .Redis_db import get_next_document_id,store_or_update_document,store_file_in_redis,check_file_claim_ids
import logging

app = FastAPI()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_file(file: UploadFile = File(...)):
    # Check if the file format is either PDF or image format
    file_extension = file.filename.split(".")[-1]
    allowed_formats = ["pdf", "jpg", "jpeg", "png", "gif"]
    if file_extension.lower() not in allowed_formats:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be in PDF or image format (JPEG, PNG, GIF).",
        )
    return file

@app.put("/processFileFast", dependencies=[Depends(authenticate)])
async def process_file(
    claim_id: Optional[str] = Query(None, description="Optional claim ID"),
    file: UploadFile = Depends(validate_file),  # Validate file format
    file_category: FileCategory = Query(..., description="Select file category"),
    _: None = Depends(check_file_claim_ids)  # Use underscore to indicate that the return value is not used
):
    priority = True
    try:
        logger.info("Starting to process file.")
        document_id = await get_next_document_id()  # Add await here
        logger.info(f"Got document ID: {document_id}")

        # Store or update the document with priority
        await store_or_update_document(  # Add await here
            document_id=document_id,
            claim_id=claim_id,
            file_id=document_id,  # Use document ID as file ID
            file_category=file_category,
            log='Processing started',
            priority=priority,
            ocr_result='No OCR result yet',
            ocr_file_path='Path to file'  # Placeholder for file path
        )

        # Store the uploaded file in Redis
        await store_file_in_redis(file, document_id)  # Add await here
        logger.info("Stored the uploaded file in Redis.")

        # Generate response body
        status_code = status.HTTP_200_OK
        file_id = document_id
        log = "Success"  # Placeholder for success log

    except Exception as e:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        file_id = None
        log = str(e)
        logger.error(f"Error processing file: {log}")

    response_body = {
        "status_code": status_code,
        "File_Id": file_id,
        "claim_id": claim_id,
        "log": log
    }

    return response_body

@app.get("/retrieveProcessedFileData", dependencies=[Depends(authenticate)])
async def retrieve_processed_file_data(File_Id: Optional[str] = Query(None, description="File ID"), claim_id: Optional[str] = Query(None, description="Claim ID"), _: None = Depends(check_file_claim_ids)):
    if not File_Id and not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either File_Id or Claim_Id.",
        )
    # Placeholder implementation to retrieve OCR data based on claim_id
    ocr_data = {"field1": "value1", "field2": "value2"}  # Placeholder OCR data
    return {"claim_id": claim_id, "ocr_data": ocr_data}

@app.get("/retrieveProcessedFile", dependencies=[Depends(authenticate)])
async def retrieve_processed_file(File_Id: Optional[str] = Query(None, description="File ID"), claim_id: Optional[str] = Query(None, description="Claim ID"), _: None = Depends(check_file_claim_ids)):
    if not File_Id and not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either File_Id or Claim_Id.",
        )
    # Placeholder implementation to retrieve processed file based on claim_id
    return {"status_code": 200, "message": f"Processed file retrieved for File ID: {File_Id or 'N/A'} and Claim ID: {claim_id or 'N/A'}"}

@app.put("/signalFileProcessed", dependencies=[Depends(authenticate)])
async def signal_file_processed(File_Id: Optional[str] = Query(None, description="File ID"), claim_id: Optional[str] = Query(None, description="Claim ID"), _: None = Depends(check_file_claim_ids)):
    if not File_Id and not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either File_Id or Claim_Id.",
        )
    # Placeholder implementation
    successful = True  # Placeholder for success status
    execution_log = f"Signal processed for File ID: {File_Id} and Claim ID: {claim_id}"  # Placeholder execution log
    return {"Successful": successful, "Execution Log": execution_log}

@app.delete("/deleteFile", dependencies=[Depends(authenticate)])
async def delete_file(File_Id: Optional[str] = Query(None, description="File ID"), claim_id: Optional[str] = Query(None, description="Claim ID"), _: None = Depends(check_file_claim_ids)):
    if not File_Id and not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either File_Id or Claim_Id.",
        )
    # Placeholder implementation
    return {"status_code": 200, "message": f"File deleted successfully for File ID: {File_Id or 'N/A'} and Claim ID: {claim_id or 'N/A'}"}

@app.put("/processFile", dependencies=[Depends(authorize_token)])
async def process_file_public(
    claim_id: Optional[str] = Query(None, description="Optional claim ID"),
    file: UploadFile = Depends(validate_file),  # Validate file format
    file_category: FileCategory = Query(..., description="Select file category"),
    _: None = Depends(check_file_claim_ids)  # Use underscore to indicate that the return value is not used
):
    # Placeholder implementation
    # Set priority automatically to False
    priority = False

    try:
        logger.info("Starting to process file.")
        document_id = await get_next_document_id()  # Add await here
        logger.info(f"Got document ID: {document_id}")

        # Store or update the document with priority
        await store_or_update_document(  # Add await here
            document_id=document_id,
            claim_id=claim_id,
            file_id=document_id,  # Use document ID as file ID
            file_category=file_category,
            log='wait for Processing',
            priority=priority,
            ocr_result='No OCR result yet',
            ocr_file_path='Path to file'  # Placeholder for file path
        )

        # Store the uploaded file in Redis
        await store_file_in_redis(file, document_id)  # Add await here
        logger.info("Stored the uploaded file in Redis.")

        # Generate response body
        status_code = status.HTTP_200_OK
        file_id = document_id
        log = "Success"  # Placeholder for success log

    except Exception as e:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        file_id = None
        log = str(e)
        logger.error(f"Error processing file: {log}")

    response_body = {
        "status_code": status_code,
        "File_Id": file_id,
        "claim_id": claim_id,
        "log": log
    }

    return response_body

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
