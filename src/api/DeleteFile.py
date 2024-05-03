from fastapi import APIRouter, Depends, status, Query, HTTPException
from typing import Optional
from ..Authenticate_token import authenticate
from ..Redis_db import check_file_claim_ids

app = APIRouter()

@app.delete("/deleteFile", dependencies=[Depends(authenticate)])
async def delete_file(File_Id: Optional[str] = Query(None, description="File ID"), claim_id: Optional[str] = Query(None, description="Claim ID"), _: None = Depends(check_file_claim_ids)):
    """
    Delete a file based on the provided File ID or Claim ID.
    If neither File ID nor Claim ID is provided, raise an HTTPException.
    """
    if not File_Id and not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either File_Id or Claim_Id.",
        )

    # Placeholder implementation
    return {"status_code": 200, "message": f"File deleted successfully for File ID: {File_Id or 'N/A'} and Claim ID: {claim_id or 'N/A'}"}
