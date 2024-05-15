import os
from fastapi import HTTPException
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta
env_path = "src/api/variables.env"
load_dotenv(env_path)

API_TOKEN_1 = os.getenv("API_TOKEN_1")
API_TOKEN_1_NAME = os.getenv("API_TOKEN_1_SUBJECT")
API_TOKEN_1_AUDIENCE = os.getenv("RESTRICTED_ENDPOINTS_API_TOKEN_1")
API_TOKEN_2 = os.getenv("API_TOKEN_2")
API_TOKEN_2_NAME = os.getenv("API_TOKEN_1_SUBJECT")
API_TOKEN_2_AUDIENCE = os.getenv("RESTRICTED_ENDPOINTS_API_TOKEN_2")
JWT_SECRET_KEY = os.getenv("SECRET_KEY")
JWT_ALGORITHM = os.getenv("ALGORITHM")
EXPIRATION_TIME_MINUTES = int(os.getenv("EXPIRATION_TIME_MINUTES"))
ISSUER = os.getenv("ISSUER")

def create_jwt_token(api_key: str):
    """
    Generates a JWT (JSON Web Token) for a given API key.
    The function sets the audience, issuer, and subject based on the API key. 
    The payload is then encoded into a JWT and returned

    """

    if api_key == API_TOKEN_1:
        audience = API_TOKEN_1_AUDIENCE
        issuer = ISSUER
        subject = API_TOKEN_1_NAME
    elif api_key == API_TOKEN_2:
        audience = API_TOKEN_2_AUDIENCE
        issuer = ISSUER
        subject = API_TOKEN_2_NAME
    else:
        raise HTTPException(status_code=400, detail="Invalid API key")

    issued_at = datetime.utcnow()
    expiration_time = issued_at + timedelta(minutes=EXPIRATION_TIME_MINUTES) 

    payload = {
        "aud": audience,
        "iss": issuer,
        "sub": subject,
        "iat": issued_at, 
        "exp": expiration_time  
    }
    jwt_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return jwt_token