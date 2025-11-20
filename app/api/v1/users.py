# app/api/v1/users.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from app.core.config import settings

router = APIRouter(prefix="/users", tags=["Users"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token error")

def require_role(role: str):
    def role_checker(user: User = Depends(get_current_user)):
        if user.role != role:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return role_checker

@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "verified": user.is_verified,
        "created_at": user.created_at
    }

# Admin endpoints
@router.get("/")
def list_users(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{"id": u.id, "email": u.email, "role": u.role, "verified": u.is_verified} for u in users]

@router.post("/promote/{user_id}")
def promote_user(user_id: int, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    target = db.query(User).get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.role = "admin"
    db.add(target)
    db.commit()
    return {"message": f"{target.email} promoted to admin"}

@router.post("/demote/{user_id}")
def demote_user(user_id: int, admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    target = db.query(User).get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.role = "user"
    db.add(target)
    db.commit()
    return {"message": f"{target.email} demoted to user"}
