from typing import Optional

from fastapi import Depends, Header, HTTPException

from .json_web_token import JsonWebToken


async def get_bearer_token(
    api_key: Optional[str] = Header(None, description="api-key"),
):
    if not api_key:
        raise HTTPException(status_code=500, detail="require api_key header")
    return api_key


def validate_token(token: str = Depends(get_bearer_token)):
    return JsonWebToken(token).validate()
