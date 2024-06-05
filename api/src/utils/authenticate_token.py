from fastapi.security import HTTPBasic
from passlib.context import CryptContext  # Import bcrypt for password hashing
from src.core.config import settings

from .log_function import logs

SECRET_USER = settings.secret_username
SECRET_PASS = settings.secret_password
SECRET_KEY = settings.secret_key
ALGORITHM = settings.algorithm
security = HTTPBasic()
# Initialize bcrypt context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password, hashed_password):
    """
    Verify a plain password against a hashed password.
    """
    try:
        result = pwd_context.verify(plain_password, hashed_password)
        logs("info", "1")
        return result
    except Exception as e:
        logs("critical", "0")
        raise


def get_password_hash(password):
    """
    Hash a password.
    """
    try:
        result = pwd_context.hash(password)
        logs("info", "1")
        return result
    except Exception as e:
        logs("critical", "0")
        raise
