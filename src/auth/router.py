from fastapi import APIRouter
from fastapi import Header, Depends, Cookie, status, Response

from src.common.database import blocked_token_db, session_db, user_db
from .schemas import *
from src.users.errors import *

from passlib.context import CryptContext

import jwt
import time
import secrets

auth_router = APIRouter(prefix="/auth", tags=["auth"])
pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24

# check authorized user
def authenticate_email_password(request: LoginRequest) -> LoginRequest:
    user = next((u for u in user_db if (u.get("email") or "").lower() == request.email.lower()), None)
    if not user:
        raise InvalidAccountException()
    if not pwd_ctx.verify(request.password, user["hashed_password"]):
        raise InvalidAccountException()
    return request

@auth_router.post("/token", status_code=status.HTTP_200_OK)
def token_based_authentication(request: LoginRequest = Depends(authenticate_email_password)):
    now = int(time.time())

    access_token_payload={
        "sub": request.email,
        "exp": now + SHORT_SESSION_LIFESPAN * 60
    }
    access_token = jwt.encode(access_token_payload, SECRET_KEY, algorithm=ALGORITHM)

    refresh_token_payload={
        "sub": request.email,
        "exp": now + LONG_SESSION_LIFESPAN * 60
    }
    refresh_token = jwt.encode(refresh_token_payload, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

def check_auth_header(authorization: str | None = Header(None)) -> str | None:
    if not authorization:
        raise UnauthenticatedException()
    if not authorization.startswith("Bearer "):
        raise AuthorizationHeaderException()
    
    return authorization
    
@auth_router.post("/token/refresh", status_code=status.HTTP_200_OK)
def refresh_token(authorization: str | None = Depends(check_auth_header)):

    refresh_token = authorization.split(" ")[1]
    if refresh_token in blocked_token_db:
        raise InvalidTokenException()
    
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user = next((u for u in user_db if u["email"] == payload.get("sub")), None)
        if not user:
            raise InvalidTokenException()
        blocked_token_db[refresh_token] = payload["exp"]

        now = int(time.time())
        access_token_payload={
            "sub": payload.get("sub"),
            "exp": now + SHORT_SESSION_LIFESPAN * 60
        }
        access_token = jwt.encode(access_token_payload, SECRET_KEY, algorithm=ALGORITHM)
        refresh_token_payload={
            "sub": payload.get("sub"),
            "exp": now + LONG_SESSION_LIFESPAN * 60
        }
        refresh_token = jwt.encode(refresh_token_payload, SECRET_KEY, algorithm=ALGORITHM)
        return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

    except jwt.ExpiredSignatureError:
        raise InvalidTokenException()
    except jwt.InvalidTokenError:
        raise InvalidTokenException()

@auth_router.delete("/token",status_code=status.HTTP_204_NO_CONTENT)
def delete_refresh_token(authorization: str | None = Depends(check_auth_header)):
    
    refresh_token = authorization.split(" ")[1]
    if any(refresh_token in token for token in blocked_token_db):
        raise InvalidTokenException()
    
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user = next((u for u in user_db if u["email"] == payload.get("sub")), None)
        if not user:
            raise InvalidTokenException()
        blocked_token_db[refresh_token] = payload["exp"]
        return

    except jwt.ExpiredSignatureError:
        raise InvalidTokenException()
    except jwt.InvalidTokenError:
        raise InvalidTokenException()

@auth_router.post("/session", status_code=status.HTTP_200_OK)
def create_session(response: Response, 
                   request: LoginRequest = Depends(authenticate_email_password)) -> Response:
    session_id = secrets.token_urlsafe(32)
    response.set_cookie(
        key="sid",
        value=session_id,
        httponly=True,
        max_age=LONG_SESSION_LIFESPAN * 60,
        secure=True,
        samesite="lax"
    )

    session_db[session_id] = {
        "email": request.email,
        "exp": int(time.time()) + LONG_SESSION_LIFESPAN * 60
        #"exp": int(time.time()) - 10
    }

    response.status_code = status.HTTP_200_OK
    return response

@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def delete_session(response: Response, sid: str | None = Cookie(None)) -> Response:
    if sid:
        session_db.pop(sid, None)
        response.delete_cookie(key="sid", path="/")

    response.status_code = status.HTTP_204_NO_CONTENT
    return response

