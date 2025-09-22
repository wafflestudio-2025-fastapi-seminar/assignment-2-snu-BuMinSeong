from pydantic import BaseModel, EmailStr

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class Tokens(BaseModel):
    access_token: str
    refresh_token: str

class Session(BaseModel):
    sid: str
    user_id: int
    exp: int

SECRET_KEY = "1"
ALGORITHM = "HS256"