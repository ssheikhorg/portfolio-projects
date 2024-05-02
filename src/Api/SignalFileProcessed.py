from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import Optional
from ..Authenticate_token import authenticate
from ..Redis_db import check_file_claim_ids

app = APIRouter()

@app.put("/signalFileProcessed", dependencies=[Depends(authenticate)])
async def signal_file_processed(File_Id: Optional[str] = Query(None, description="File ID"), claim_id: Optional[str] = Query(None, description="Claim ID"), _: None = Depends(check_file_claim_ids)):
    """
    This function signals that a file has been processed based on the provided File ID or Claim ID.
    If neither File ID nor Claim ID is provided, it raises an HTTPException.
    If the process is successful, it returns a response body with a success status and an execution log.
    """
    if not File_Id and not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either File_Id or Claim_Id.",
        )

    # Placeholder implementation
    successful = True  # Placeholder for success status
    execution_log = f"Signal processed for File ID: {File_Id or 'N/A'} and Claim ID: {claim_id or 'N/A'}"

    return {"Successful": successful, "Execution Log": execution_log}
