from pydantic import BaseModel, EmailStr
import os

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

SECRET_KEY = os.getenv("SECRET_KEY", "default_secret_key")
ALGORITHM = "HS256"