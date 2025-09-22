from pydantic import BaseModel, EmailStr

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class Tokens(BaseModel):
    access_token: str
    refresh_token: str

class TokenStructure(BaseModel):
    iss: str
    sub: str
    aud: str
    exp: float
    iat: float

class Session(BaseModel):
    sid: str
    user_id: int
    exp: float

SECRET_KEY = "1"
ALGORITHM = "HS256"