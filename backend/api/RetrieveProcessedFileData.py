from fastapi import APIRouter, Depends, status, Query, HTTPException
from typing import Optional
from ..utils.authenticate_token import authorize_token
from ..utils.process_files import check_file_claim_ids

app = APIRouter()

@app.get("/retrieveProcessedFileData", dependencies=[Depends(authorize_token)])
async def retrieve_processed_file_data(
    File_Id: Optional[str] = Query(None, description="File ID"),
    claim_id: Optional[str] = Query(None, description="Claim ID"),
    payload: dict = Depends(authorize_token)
):
    

    """
    Retrieves and returns OCR data for a processed file using the provided File ID or Claim ID.

    """

    # Check if the endpoint name matches any of the endpoints in the aud claim of the payload
    if payload.get('aud'):
        aud_endpoints = payload['aud'].split(',')
        if any(endpoint.strip() == '/retrieveProcessedFileData' for endpoint in aud_endpoints):
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

    # Placeholder implementation to retrieve OCR data based on claim_id
    ocr_data = {"field1": "value1", "field2": "value2"}  # Placeholder OCR data
    return {"claim_id": claim_id, "ocr_data": ocr_data}
