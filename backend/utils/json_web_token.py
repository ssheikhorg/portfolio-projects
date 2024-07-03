from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import jwt
from config import settings
from fastapi import Depends, Header, HTTPException

from .custom_exceptions import BadCredentialsException


@dataclass
class JsonWebToken:
    """Perform JSON Web Token (JWT) validation using PyJWT"""

    jwt_access_token: str
    secret_key: str = settings.secret_key
    algorithm: str = settings.algorithm
    issuer: str = settings.issuer

    def validate(self):
        try:
            payload = jwt.decode(
                self.jwt_access_token,
                self.secret_key,
                algorithms=[self.algorithm],
            )

            issuer = payload.get("iss")
            subject = payload.get("sub")
            issued_at = payload.get("iat")
            expiration_time = payload.get("exp")

            if issuer != self.issuer:
                raise HTTPException(status_code=400, detail="Invalid token issuer")

            if datetime.utcnow() > datetime.utcfromtimestamp(expiration_time):
                raise HTTPException(status_code=400, detail="Token has expired")

            return {"subject": subject, "issuer": issuer}

        except jwt.PyJWTError:
            raise BadCredentialsException
