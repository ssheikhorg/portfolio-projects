from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
import os
import jwt
from passlib.context import CryptContext  # Import bcrypt for password hashing
from .log_function import logs
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a file handler and set its level to INFO
file_handler = logging.FileHandler('logfile.log')
file_handler.setLevel(logging.INFO)

# Create a formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Set the formatter for the file handler
file_handler.setFormatter(formatter)

# Add the file handler to the root logger
logging.getLogger().addHandler(file_handler)

env_path = "src/api/variables.env"
load_dotenv(env_path)
SECRET_USER= os.getenv("SECRET_USERNAME")
SECRET_PASS = os.getenv("SECRET_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
security = HTTPBasic()
# Initialize bcrypt context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    """
    Verify a plain password against a hashed password.
    """
    try:
        result = pwd_context.verify(plain_password, hashed_password)
        logs('info', "1")
        return result
    except Exception as e:
        logs('critical',"0")
        raise

def get_password_hash(password):
    """
    Hash a password.
    """
    try:
        result = pwd_context.hash(password)
        logs('info', "1")
        return result
    except Exception as e:
        logs('critical', "0")
        raise

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    """
    Authenticate a user based on their credentials.
    If the username or password is incorrect, raise an HTTPException.
    """
    try:
        correct_username = SECRET_USER
        correct_password_hash = get_password_hash(SECRET_PASS) 
        print("hashed", correct_password_hash) # Hash the correct password
        if credentials.username != correct_username or not verify_password(credentials.password, correct_password_hash):
            logs('warning', "Incorrect username or password in authenticate function")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"},
            )
        logs('info', "Successful authentication in authenticate function")
        logs('info', "1")
        return True
    except Exception as e:
        logs('critical', "0")
        raise

public_security = HTTPBearer()

def authorize_token(credentials: HTTPAuthorizationCredentials = Depends(public_security)):
    """
    Authorize a token.
    If the token is expired or invalid, raise an HTTPException.
    """
    try:
        token = credentials.credentials
        if not SECRET_KEY:
            raise ValueError("SECRET_KEY is not set")
        Get_Audience = jwt.decode(token, SECRET_KEY, options={"verify_signature": False})
        # Extract the audience from the payload
        Expected_Audience = Get_Audience.get('aud', None)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], audience=str(Expected_Audience),options={"verify_signature": True})
        
        print("Payload",payload)
        logs('info', "Token successfully decoded in authorize_token function")
        logs('info', "1")
        return payload  # Return the decoded payload if the token is valid
    except jwt.ExpiredSignatureError:
        logs('critical', "Token has expired in authorize_token function")
        logs('critical', "0")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        logs('critical', "Invalid token in authorize_token function")
        logs('critical', "0")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except ValueError as e:
        logs('critical', str(e))
        logs('critical', "0")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
