from datetime import datetime, timedelta

import jwt
from config import settings
from fastapi import HTTPException


def get_token_info(api_key):
    api_data = settings.api_tokens
    for token in api_data:
        if token["api_key"] == api_key:
            return token
    return None


def create_jwt_token(api_key: str):
    """
    Generates a JWT (JSON Web Token) for a given API key.
    The function sets the issuer and subject based on the API key.
    The payload is then encoded into a JWT and returned.
    """
    token_info = get_token_info(api_key)
    if token_info is None:
        raise HTTPException(status_code=400, detail="Invalid API key")

    issuer = settings.issuer
    subject = token_info["subject"]

    issued_at = datetime.utcnow()
    expiration_time = issued_at + timedelta(minutes=settings.expiration_time_minutes)

    payload = {"iss": issuer, "sub": subject, "iat": issued_at, "exp": expiration_time}

    jwt_token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)

    return jwt_token
