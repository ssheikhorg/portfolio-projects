from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import jwt
from config import settings
from fastapi import Depends, Header, HTTPException

from .custom_exceptions import BadCredentialsException
from .issue_token import get_token_info


@dataclass
class JsonWebToken:
    """Perform JSON Web Token (JWT) validation using PyJWT"""

    jwt_access_token: str
    secret_key: str = settings.secret_key
    algorithm: str = settings.algorithm
    issuer: str = settings.issuer

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
