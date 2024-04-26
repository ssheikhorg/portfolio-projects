from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi import  Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
import os
import jwt
env_path= "src/Variables.env"
load_dotenv(env_path)

security = HTTPBasic()
SECRET_USERNAME = os.getenv("SECRET_USERNAME")
SECRET_PASSWORD = os.getenv("SECRET_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = SECRET_USERNAME
    correct_password = SECRET_PASSWORD
    if credentials.username != correct_username or credentials.password != correct_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True

public_security = HTTPBearer()

def authorize_token(credentials: HTTPAuthorizationCredentials = Depends(public_security)):
    # Placeholder logic for token validation (e.g., validate against a database or JWT)
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # Return the decoded payload if the token is valid
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

