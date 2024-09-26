from typing import Optional

import jwt
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .custom_exceptions import BadCredentialsException

from config import settings


class JWTAdmin:
    def __init__(self, jwt_token: str):
        self.jwt_access_token: str = jwt_token
        self.secret_key: str = settings.secret_key
        self.algorithm: str = settings.algorithm
        self.issuer: str = settings.issuer

    def get_token_info(self, api_key: str) -> Optional[dict]:  # noqa
        api_data = settings.api_tokens
        for token in api_data:
            if token["api_key"] == api_key:
                return token
        return None

    def create_jwt_token(self) -> str:
        token_info = self.get_token_info(self.jwt_access_token)
        if token_info is None:
            raise HTTPException(status_code=400, detail="Invalid API key")

        issuer = settings.issuer
        subject = token_info["subject"]
        issued_at = datetime.now(timezone.utc)
        expiration_time = issued_at + timedelta(minutes=settings.expiration_time_minutes)
        payload = {"iss": issuer, "sub": subject, "iat": issued_at, "exp": expiration_time}
        jwt_token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)
        return jwt_token

    def validate(self):
        for token in settings.api_tokens:
            if self.jwt_access_token == token["api_key"]:
                return {"subject": token["subject"], "issuer": "fixed_token"}

        # if not matched in fixed tokens, validate the token
        try:
            payload = jwt.decode(
                self.jwt_access_token,
                self.secret_key,
                algorithms=[self.algorithm],
            )

            issuer = payload.get("iss")
            subject = payload.get("sub")
            expiration_time = payload.get("exp")
            current_utc_time = datetime.now(timezone.utc)

            if issuer != self.issuer:
                raise HTTPException(status_code=400, detail="Invalid token issuer")

            if current_utc_time > datetime.fromtimestamp(expiration_time, tz=timezone.utc):
                raise HTTPException(status_code=400, detail="Token has expired")

            return {"subject": subject, "issuer": issuer}

        except jwt.PyJWTError:
            raise BadCredentialsException


def validate_token(credentials: HTTPAuthorizationCredentials = Security(HTTPBearer())):
    token = credentials.credentials
    jwt_credentials = JWTAdmin(token)
    return jwt_credentials.validate()
