from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from utils.authenticate_token import authenticate
from utils.issue_token import create_jwt_token
import logging

''' We should define a global logger
'''
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Format of the log messages
                    handlers=[
                        logging.StreamHandler() 
                    ])

router = APIRouter()
logger = logging.getLogger(__name__)

class TokenResponse(BaseModel):
    status: str
    token: str

@router.post("/issueToken", dependencies=[Depends(authenticate)], response_model=TokenResponse)
async def issue_token(api_key: str = Query(...)):
''' Issues a JWT token from the given API key.
    
    Args:
        api_key (str): The API key to generate the JWT token.
    Returns:
        dict: A dictionary with the status and the JWT token.
'''
    try:
        jwt_token = create_jwt_token(api_key)
        return {"status": "success", "token": jwt_token}
    except HTTPException as http_exception:
        logger.error(f"HTTP exception occurred: {http_exception.detail}")
        raise http_exception
    except KeyError:
        logger.error(f"API key not found: {api_key}")
        raise HTTPException(status_code=404, detail="API key not found")
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
