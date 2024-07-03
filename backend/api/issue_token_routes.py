from fastapi import APIRouter, HTTPException, Query, Depends
from utils.issue_token import create_jwt_token

app = APIRouter()

def get_jwt_token_creator():
    """
    Dependency function to get the JWT token creator function.
    This allows for easier testing and flexibility.
    """
    return create_jwt_token

@app.post("/issueToken")
async def issue_token(api_key: str = Query(...), create_token=Depends(get_jwt_token_creator)):
    """
    Issues a JWT token from the given API key.

    Parameters:
    - api_key (str): The API key to generate the token from.

    Returns:
    - dict: A dictionary with the status and the generated JWT token.
    """
    try:
        jwt_token = create_token(api_key)
        return {"status": "success", "token": jwt_token}
    except HTTPException as http_exception:
        raise http_exception
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
