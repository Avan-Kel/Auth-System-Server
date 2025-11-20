# app/schemas/user.py
from pydantic import BaseModel, EmailStr, constr

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    # limit string length to ensure bcrypt never receives >72 bytes
    password: constr(min_length=8, max_length=72)

class UserRead(UserBase):
    id: int
    role: str
    is_verified: bool

    class Config:
        orm_mode = True

class UserLogin(UserBase):
    password: constr(min_length=8, max_length=72)

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
