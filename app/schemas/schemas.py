from pydantic import BaseModel, EmailStr
from typing import Optional

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    email: str
    public_key: str

    class Config:
        from_attributes = True

class PasswordEntryCreate(BaseModel):
    website: str
    email: str
    password: str

class PasswordEntryResponse(BaseModel):
    id: str
    website: str
    email: str
    password: str
    difficulty: str
    owner_id: str

    class Config:
        from_attributes = True

class PasswordGenerateQuery(BaseModel):
    length: int = 16
    symbols: bool = True
    numbers: bool = True
    uppercase: bool = True
    lowercase: bool = True
