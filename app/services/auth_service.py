# app/services/auth_service.py
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token_for_user,
    create_refresh_token_string,
    create_refresh_jwt,
    decode_token,
    create_verification_token,
    create_password_reset_token,
)
from fastapi import HTTPException

def register_user(db: Session, email: str, password: str, role: str = "user"):
    # Check if user already exists
    exists = db.query(User).filter(User.email == email).first()
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash password safely (72-byte limit handled in hash_password)
    hashed_pw = hash_password(password)

    # Create new user
    new_user = User(email=email, hashed_password=hashed_pw, role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def authenticate_user(db: Session, email: str, password: str):
    # Fetch user
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Create refresh token string and persist
    refresh_str = create_refresh_token_string()
    rt = RefreshToken(token=refresh_str, user_id=user.id)
    db.add(rt)
    db.commit()
    db.refresh(rt)

    # Create access token and refresh JWT
    access = create_access_token_for_user(user)
    refresh_jwt = create_refresh_jwt(refresh_str)
    return access, refresh_jwt, user

def rotate_refresh_token(db: Session, old_refresh_jwt: str):
    payload = decode_token(old_refresh_jwt)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    old_token_str = payload.get("token")
    db_rt = db.query(RefreshToken).filter(
        RefreshToken.token == old_token_str,
        RefreshToken.revoked == False
    ).first()
    if not db_rt:
        raise HTTPException(status_code=401, detail="Refresh token revoked or not found")

    # Revoke old token
    db_rt.revoked = True
    db.add(db_rt)

    # Create new refresh record
    new_refresh_str = create_refresh_token_string()
    new_rt = RefreshToken(token=new_refresh_str, user_id=db_rt.user_id)
    db.add(new_rt)
    db.commit()
    db.refresh(new_rt)

    # Generate new access and refresh tokens
    user = db.query(User).get(db_rt.user_id)
    access = create_access_token_for_user(user)
    refresh_jwt = create_refresh_jwt(new_refresh_str)
    return access, refresh_jwt

def revoke_refresh_token(db: Session, token_str: str):
    db_rt = db.query(RefreshToken).filter(RefreshToken.token == token_str).first()
    if db_rt:
        db_rt.revoked = True
        db.add(db_rt)
        db.commit()
    return True

def create_email_verification(email: str):
    return create_verification_token(email)

def create_password_reset(email: str):
    return create_password_reset_token(email)
