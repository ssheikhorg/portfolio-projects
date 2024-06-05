import tempfile

import jwt
from fastapi import Depends, File, HTTPException, UploadFile, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)
from src.utils.authenticate_token import get_password_hash, verify_password
from src.utils.log_function import logs

import yara

from .config import settings

SECRET_USER = settings.secret_username
SECRET_PASS = settings.secret_password
SECRET_KEY = settings.secret_key
ALGORITHM = settings.algorithm
security = HTTPBasic()


def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    """
    Authenticate a user based on their credentials.
    If the username or password is incorrect, raise an HTTPException.
    """
    try:
        correct_username = SECRET_USER
        correct_password_hash = get_password_hash(SECRET_PASS)
        print("hashed", correct_password_hash)  # Hash the correct password
        if credentials.username != correct_username or not verify_password(
            credentials.password, correct_password_hash
        ):
            logs("warning", "Incorrect username or password in authenticate function")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )
        logs("info", "Successful authentication in authenticate function")
        logs("info", "1")
        return True
    except Exception as e:
        logs("critical", "0")
        raise


public_security = HTTPBearer()


def authorize_token(
    credentials: HTTPAuthorizationCredentials = Depends(public_security),
):
    """
    Authorize a token.
    If the token is expired or invalid, raise an HTTPException.
    """
    try:
        token = credentials.credentials
        if not SECRET_KEY:
            raise ValueError("SECRET_KEY is not set")

        # Decode the token with signature verification
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        print("Payload", payload)
        logs("info", "Token successfully decoded in authorize_token function")
        return payload  # Return the decoded payload if the token is valid
    except jwt.ExpiredSignatureError:
        logs("critical", "Token has expired in authorize_token function")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        logs("critical", "Invalid token in authorize_token function")
        logs("critical", "0")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except ValueError as e:
        logs("critical", str(e))
        logs("critical", "0")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# Dependency function
def yara_match(file: UploadFile = File(...)):
    # Load YARA rules and apply to files
    pass
