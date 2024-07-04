from fastapi import APIRouter, HTTPException, Query
from utils.issue_token import create_jwt_token

router = APIRouter()


@router.post("/issueToken")
async def issue_token(api_key: str = Query(...)):
    """
    Issues a JWT token from the given api key

    """
    try:
        jwt_token = create_jwt_token(api_key)
        return {"status": "success", "token": jwt_token}
    except HTTPException as http_exception:
        raise http_exception
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
