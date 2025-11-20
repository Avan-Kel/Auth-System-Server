# app/api/v1/auth.py
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.user import UserCreate, UserLogin, TokenResponse
from app.services.auth_service import register_user, authenticate_user, rotate_refresh_token, create_email_verification, create_password_reset, revoke_refresh_token
from app.utils.email_sender import send_email
from app.core.security import decode_token
from app.models.user import User
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["Auth"])

class RefreshRequest(BaseModel):
    refresh_token: str

class ResetRequest(BaseModel):
    email: str

class ResetConfirm(BaseModel):
    token: str
    password: str

@router.post("/register")
def register(payload: UserCreate, db: Session = Depends(get_db)):
    user = register_user(db, payload.email, payload.password)
    # send verification email
    token = create_email_verification(user.email)
    verify_link = f"{'http://localhost:3000'}/verify-email?token={token}"
    html = f"<p>Welcome! Verify: <a href='{verify_link}'>Click to verify</a></p>"
    send_email(user.email, "Verify your email", html)
    return {"message": "Registration successful. Check your email for verification."}

@router.post("/login", response_model=TokenResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    access, refresh_jwt, user = authenticate_user(db, payload.email, payload.password)
    return TokenResponse(access_token=access, refresh_token=refresh_jwt)

@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)):
    access, refresh_jwt = rotate_refresh_token(db, body.refresh_token)
    return TokenResponse(access_token=access, refresh_token=refresh_jwt)

@router.post("/logout")
def logout(body: RefreshRequest, db: Session = Depends(get_db)):
    # revoke given refresh token string
    payload = decode_token(body.refresh_token)
    token_str = payload.get("token") if payload else None
    if token_str:
        revoke_refresh_token(db, token_str)
    return {"message": "Logged out"}

@router.post("/request-password-reset")
def request_password_reset(body: ResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if user:
        token = create_password_reset(user.email)
        reset_link = f"{'http://localhost:3000'}/reset-password?token={token}"
        html = f"<p>Reset your password: <a href='{reset_link}'>Reset</a></p>"
        send_email(user.email, "Password reset", html)
    # Always return same message to avoid account enumeration
    return {"message": "If that email exists, a reset link has been sent."}

@router.post("/reset-password")
def reset_password(body: ResetConfirm, db: Session = Depends(get_db)):
    payload = decode_token(body.token)
    if not payload or payload.get("type") != "reset":
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")
    user.hashed_password = __import__("app.core.security", fromlist=["hash_password"]).hash_password(body.password)
    db.add(user)
    db.commit()
    return {"message": "Password has been reset."}

@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    payload = decode_token(token)
    if not payload or payload.get("type") != "verify":
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_verified = True
    db.add(user)
    db.commit()
    return {"message": "Email verified."}
