from fastapi import APIRouter
from fastapi import Header, Depends, Cookie, status

from common.database import blocked_token_db, session_db, user_db
from schemas import LoginRequest, Token
from src.users.errors import *

from argon2 import PasswordHasher
from passlib.context import CryptContext

from jose import jwt, JWTError, ExpiredSignatureError
import time

auth_router = APIRouter(prefix="/auth", tags=["auth"])
ph = PasswordHasher()

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60
SECRET_KEY = 1

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

# check authorized user
def authenticate_email_password(request: LoginRequest) -> LoginRequest:
    user = next((u for u in user_db if (u.get("email") or "").lower() == request.email.lower()), None)
    if not user:
        raise InvalidAccountException()
    if not pwd_ctx.verify(request.password, user["hashed_password"]):
        raise InvalidAccountException()
    return request

# check bearer header
def get_bearer_token(authorization: str | None = Header(None)):
    if not authorization:
        raise UnauthenticatedException()
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthorizationHeaderException()
    return parts[1]

@auth_router.post("/token", status_code=status.HTTP_200_OK)
def token_based_authentication(request: LoginRequest = Depends(authenticate_email_password)) -> Token:
    access_token_header={
        "typ": "JWT",
        "alg": "HS256"
    }
    access_token_payload={
        "sub": request.email,
        "exp": time.time() + SHORT_SESSION_LIFESPAN * 60
    }
    access_token = jwt.encode(access_token_header, access_token_payload, SECRET_KEY)

    refresh_token_header={
        "typ": "JWT",
        "alg": "HS256"
    }
    refresh_token_payload={
        "sub": request.email,
        "exp": time.time() + LONG_SESSION_LIFESPAN * 60
    }
    refresh_token = jwt.encode(refresh_token_header, refresh_token_payload, SECRET_KEY)
    return Token(
        access_token = access_token,
        refresh_token = refresh_token
    )

@auth_router.post("/token/refresh", status_code=status.HTTP_200_OK)
def token_refresh(refresh_token: str = Depends(get_bearer_token)) -> Token:
    try:
        payload = jwt.decode(
            refresh_token,
            SECRET_KEY,
            algorithms="HS256",
        )
        return payload
    except ExpiredSignatureError:
        raise InvalidTokenException()
    except JWTError:
        raise InvalidTokenException()

@auth_router.delete("/token",status_code=status.HTTP_204_NO_CONTENT)


@auth_router.post("/session", status_code=status.HTTP_200_OK)


@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def ftn():
    pass

