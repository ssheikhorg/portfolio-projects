from fastapi import APIRouter,  Depends, status, Query,HTTPException,status
from typing import Optional
from ..Authenticate_token import authenticate
from ..Redis_db import check_file_claim_ids

app = APIRouter()

@app.get("/retrieveProcessedFile", dependencies=[Depends(authenticate)])
async def retrieve_processed_file(File_Id: Optional[str] = Query(None, description="File ID"), claim_id: Optional[str] = Query(None, description="Claim ID"), _: None = Depends(check_file_claim_ids)):
    """
    This function retrieves a processed file based on the provided File ID or Claim ID.
    If neither File ID nor Claim ID is provided, it raises an HTTPException.
    If the process is successful, it returns a response body with the status code and a message indicating the File ID and Claim ID for which the file was retrieved.
    """
    if not File_Id and not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either File_Id or Claim_Id.",
        )

    # Placeholder implementation to retrieve processed file based on claim_id
    return {"status_code": 200, "message": f"Processed file retrieved for File ID: {File_Id or 'N/A'} and Claim ID: {claim_id or 'N/A'}"}
