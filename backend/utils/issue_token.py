import os
from fastapi import HTTPException
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta
import json

# Load environment variables from .env file
env_path = "backend/api/variables.env"
load_dotenv(env_path)

# Retrieve environment variables
JWT_SECRET_KEY = os.getenv("SECRET_KEY")
JWT_ALGORITHM = os.getenv("ALGORITHM")
EXPIRATION_TIME_MINUTES = int(os.getenv("EXPIRATION_TIME_MINUTES"))
ISSUER = os.getenv("ISSUER")
API_TOKENS_STR = os.getenv("API_TOKENS")

# Parse the JSON string into a list of dictionaries
API_TOKENS = json.loads(API_TOKENS_STR)

def get_token_info(api_key):
    for token in API_TOKENS:
        if token['api_key'] == api_key:
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

    issuer = ISSUER
    subject = token_info['subject']

    issued_at = datetime.utcnow()
    expiration_time = issued_at + timedelta(minutes=EXPIRATION_TIME_MINUTES)

    payload = {
        "iss": issuer,
        "sub": subject,
        "iat": issued_at,
        "exp": expiration_time
    }

    jwt_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return jwt_token
