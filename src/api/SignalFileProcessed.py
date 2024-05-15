from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import Optional
from ..utils.authenticate_token import authorize_token
from ..utils.process_files import check_file_claim_ids

app = APIRouter()

@app.put("/signalFileProcessed", dependencies=[Depends(authorize_token)])
async def signal_file_processed(
    File_Id: Optional[str] = Query(None, description="File ID"),
    claim_id: Optional[str] = Query(None, description="Claim ID"),
    payload: dict = Depends(authorize_token)
):
    """    
    Signals that a file has been processed and returns a success status and execution log.

    """
    # Check if the endpoint name matches any of the endpoints in the aud claim of the payload
    if payload.get('aud'):
        aud_endpoints = payload['aud'].split(',')
        if any(endpoint.strip() == '/signalFileProcessed' for endpoint in aud_endpoints):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Access restricted for this endpoint",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if not File_Id and not claim_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either File_Id or Claim_Id.",
        )

    # Placeholder implementation
    successful = True  # Placeholder for success status
    execution_log = f"Signal processed for File ID: {File_Id or 'N/A'} and Claim ID: {claim_id or 'N/A'}"

    return {"Successful": successful, "Execution Log": execution_log}
