import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException

from errors import *

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    bio: str | None = None
    height: float

    @field_validator('password', mode='after')
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            raise InvalidPasswordException()
        return v
    
    @field_validator('phone_number', mode='after')
    def validate_phone_number(cls, v: str) -> str:
        pattern = r"^010-\d{4}-\d{4}$"
        if not re.fullmatch(pattern, v):
            raise InvalidPhonenumberException()
        return v

    @field_validator('bio', mode='after')
    def validate_bio(cls, v: str|None) -> str|None:
        if v is not None and len(v) > 500:
            raise InvalidBioException()
        return v

class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float

class Authorization(BaseModel):
    auth_type: str
    session_id: str | None = None
    auth_token: str | None = None
    
    @field_validator('auth_type', mode='after')
    def validate_auth_type(cls, v:str) -> str:
        allowed = {"session_id", "token"}
        if v not in allowed:
            raise ValueError()
        return v
        