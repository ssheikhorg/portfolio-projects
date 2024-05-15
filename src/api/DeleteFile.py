from fastapi import APIRouter, Depends, status, Query, HTTPException
from typing import Optional
from ..utils.authenticate_token import authorize_token

app = APIRouter()

@app.delete("/deleteFile", dependencies=[Depends(authorize_token)])
async def delete_file(
    File_Id: Optional[str] = Query(None, description="File ID"),
    claim_id: Optional[str] = Query(None, description="Claim ID"),
    payload: dict = Depends(authorize_token)
):
    """
    
    Delete a file based on the provided File ID or Claim ID

    """
    # Check if the endpoint name matches any of the endpoints in the aud claim of the payload
    if payload.get('aud'):
        aud_endpoints = payload['aud'].split(',')
        if any(endpoint.strip() == '/deleteFile' for endpoint in aud_endpoints):
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
    return {"status_code": 200, "message": f"File deleted successfully for File ID: {File_Id or 'N/A'} and Claim ID: {claim_id or 'N/A'}"}
