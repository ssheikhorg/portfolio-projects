from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
import os
import jwt
from passlib.context import CryptContext  # Import bcrypt for password hashing
from src.utils.Logging import logs

env_path = "src/Variables.env"
load_dotenv(env_path)

security = HTTPBasic()
SECRET_USERNAME = os.getenv("SECRET_USERNAME")
SECRET_PASSWORD = os.getenv("SECRET_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

# Initialize bcrypt context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    """
    Verify a plain password against a hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """
    Hash a password.
    """
    return pwd_context.hash(password)

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    """
    Authenticate a user based on their credentials.
    If the username or password is incorrect, raise an HTTPException.
    """
    correct_username = SECRET_USERNAME
    correct_password_hash = get_password_hash(SECRET_PASSWORD)  # Hash the correct password
    if credentials.username != correct_username or not verify_password(credentials.password, correct_password_hash):
        logs('warning', "Incorrect username or password in authenticate function")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    logs('info', "Successful authentication in authenticate function")
    return True

public_security = HTTPBearer()

def authorize_token(credentials: HTTPAuthorizationCredentials = Depends(public_security)):
    """
    Authorize a token.
    If the token is expired or invalid, raise an HTTPException.
    """
    # Placeholder logic for token validation (e.g., validate against a database or JWT)
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logs('info', "Token successfully decoded in authorize_token function")
        return payload  # Return the decoded payload if the token is valid
    except jwt.ExpiredSignatureError:
        logs('critical', "Token has expired in authorize_token function")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        logs('critical', "Invalid token in authorize_token function")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
