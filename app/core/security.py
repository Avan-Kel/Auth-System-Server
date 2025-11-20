# app/core/security.py
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from app.core.config import settings
import secrets

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# temporary version for testing ONLY
def hash_password(password: str) -> str:
    return password  # store plain password temporarily

def verify_password(plain: str, hashed: str) -> bool:
    return plain == hashed



# JWT token helpers
def _create_token(payload: dict, expires_delta: timedelta) -> str:
    to_encode = payload.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def create_access_token_for_user(user) -> str:
    data = {"sub": str(user.email), "role": user.role, "type": "access"}
    return _create_token(data, timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))

def create_refresh_token_string() -> str:
    return secrets.token_urlsafe(64)

def create_refresh_jwt(token_str: str) -> str:
    data = {"token": token_str, "type": "refresh"}
    return _create_token(data, timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))

def create_verification_token(email: str) -> str:
    data = {"sub": email, "type": "verify"}
    return _create_token(data, timedelta(days=1))

def create_password_reset_token(email: str) -> str:
    data = {"sub": email, "type": "reset"}
    return _create_token(data, timedelta(hours=2))

def decode_token(token: str):
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except Exception:
        return None
