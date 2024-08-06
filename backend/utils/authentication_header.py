from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .json_web_token import JsonWebToken

security = HTTPBearer()


def validate_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    return JsonWebToken(token).validate()
