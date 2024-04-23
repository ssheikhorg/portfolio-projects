import redis
from fastapi import FastAPI, Depends, HTTPException, status, File, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, time
from celery import Celery
from models import FileCategory, ProcessFileRequest
from fastapi import Query, UploadFile
from typing import Optional

app = FastAPI()

# Security for private endpoints (HTTP Basic Authentication)
security = HTTPBasic()

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = "webapp"
    correct_password = "ocrapp"
    if credentials.username != correct_username or credentials.password != correct_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True

# Create a redis client
redis_client = redis.Redis(host='172.30.80.1', port=6379, db=0)

# Define a Celery instance
celery_app = Celery('tasks', broker='redis://172.30.80.1:6379/1')

# Test the connection
print(redis_client.ping())

# Define a function to get the next available document ID
def get_next_document_id():
    # Get the current highest document ID
    highest_id = redis_client.get('highest_document_id')
    if highest_id is None:
        # If no documents exist, start from ID 1
        document_id = 1
    else:
        # Increment the highest ID and return
        document_id = int(highest_id.decode()) + 1
    redis_client.set('highest_document_id', document_id)
    return document_id

# Define a function to store or update a document
def store_or_update_document(document_id, claim_id, file_id, file_category, log, priority, ocr_result, ocr_file_path):
    # Create a hash for the document
    redis_client.hmset(f'document:{document_id}', {
        'claim_id': claim_id,
        'file_id': file_id,
        'file_category': file_category.value,
        'log': log,
        'priority': str(priority),
        'ocr_result': ocr_result,
        'ocr_file_path': ocr_file_path
    })

    # Create helper index with claim_id and File_Id as keys
    if claim_id:
        redis_client.set(f'claim_index:{claim_id}', document_id)
    if file_id:
        redis_client.set(f'file_index:{file_id}', document_id)

    # Print the stored or updated document
    stored_document = redis_client.hgetall(f'document:{document_id}')
    print(f"Document {document_id}: {stored_document}")

# Define a Celery task for processing files
@celery_app.task
def process_file_task(document_id, priority):
    # Placeholder implementation
    if priority:
        print(f"Processing file with document ID {document_id} immediately.")
        # Your processing logic here
    else:
        print(f"Scheduling file with document ID {document_id} for off-peak hours.")
        # Scheduling logic here

# Define a function to store the uploaded file in Redis
def store_file_in_redis(file: UploadFile, document_id: int):
    # Read the file contents as bytes
    file_contents = file.file.read()

    # Store the file contents in Redis using document_id as the key
    redis_client.set(f'file:{document_id}', file_contents)

    # Check priority for scheduling
    priority = True  # Placeholder for priority determination, replace with your logic
    if priority:
        # Schedule task for immediate processing
        process_file_task.apply_async(args=[document_id, priority])
    else:
        # Schedule task for off-peak hours (10 PM to 7 AM Germany time zone)
        off_peak_time = datetime.combine(datetime.now().date(), time(22, 0))  # 10 PM
        process_file_task.apply_async(args=[document_id, priority], eta=off_peak_time)

async def check_file_claim_ids(claim_id: Optional[str] = Query(None, description="Claim ID")):
    if not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a claimID",
        )

# Security for public endpoints (Bearer Token Authentication)
public_security = HTTPBearer()

def authorize_token(credentials: HTTPAuthorizationCredentials = Depends(public_security)):
    # Placeholder logic for token validation (e.g., validate against a database or JWT)
    token = credentials.credentials
    if not token == "TOKEN":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True

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
    request: ProcessFileRequest
):
    # Set priority automatically to True
    priority = True

    # Get the next available document ID
    document_id = get_next_document_id()

    # Store or update the document with priority
    store_or_update_document(
        document_id=document_id,
        claim_id=request.claim_id,
        file_id=document_id,  # Use document ID as file ID
        file_category=request.file_category,
        log='No log yet',
        priority=priority,
        ocr_result='No OCR result yet',
        ocr_file_path='Path to file'  # Placeholder
    )

    # Store the uploaded file in Redis
    store_file_in_redis(request.file, document_id)

    # Generate response body
    status_code = status.HTTP_200_OK
    file_id = document_id
    log = "True"  # Placeholder for success log

    response_body = {
        "status_code": status_code,
        "File_Id": file_id,
        "claim_id": request.claim_id,
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

    # Get the next available document ID
    document_id = get_next_document_id()

    # Store or update the document with priority
    store_or_update_document(
        document_id=document_id,
        claim_id=claim_id,
        file_id=document_id,  # Use document ID as file ID
        file_category=file_category,
        log='No log yet',
        priority=priority,
        ocr_result='No OCR result yet',
        ocr_file_path='Path to file'  # Placeholder for file path
    )

    # Store the uploaded file in Redis
    store_file_in_redis(file, document_id)

    # Generate response body
    status_code = status.HTTP_200_OK
    file_id = document_id
    log = "True"  # Placeholder for success log

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
