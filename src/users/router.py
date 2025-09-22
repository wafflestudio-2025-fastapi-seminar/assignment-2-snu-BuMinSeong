import time

from typing import Annotated

import jwt
from argon2 import PasswordHasher
from src.auth.schemas import SECRET_KEY, ALGORITHM


from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status,
    Request
)

from src.users.schemas import CreateUserRequest, UserResponse, Authorization
from common.database import blocked_token_db, session_db, user_db
from src.users.errors import *

user_router = APIRouter(prefix="/users", tags=["users"])
ph = PasswordHasher()

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    
    # Handles Email Repeatition Exception
    for user in user_db:
        if user["email"] == request.email:
            raise InvalidEmailException()
        
    hashed_password = ph.hash(request.password)

    user_id = len(user_db) + 1
    user = request.model_dump(exclude={"password"}, by_alias=False)
    user.update({"user_id": user_id, "hashed_password": hashed_password})

    user_db.append(user)

    return UserResponse(
        user_id=user_id,
        name=request.name,
        email=request.email,
        phone_number=request.phone_number,
        height=request.height,
        bio=request.bio
    )

def get_current_user(request: Request) -> Authorization:
    # authorize with session id
    session_id = request.cookies.get("sid")
    if session_id:
        return Authorization(
            auth_type="session_id",
            session_id=session_id
        )
    # authorize with authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header:
        if not auth_header.startswith("Bearer "):
            raise AuthorizationHeaderException()
        token = auth_header.split(" ")[1]
        return Authorization(
            auth_type="token",
            auth_token=token
        )
    
    raise UnauthenticatedException()

@user_router.get("/me", status_code=status.HTTP_200_OK)
def get_user_info(authorization: Authorization =  Depends(get_current_user)) -> UserResponse:
    if authorization.auth_type == "session_id":
        session_id = authorization.session_id
        session = next((s for s in session_db if s["sid"] == session_id), None)
        
        if not session or session["exp"] < int(time.time()):
            raise InvalidSessionException()
        
        user = next((u for u in user_db if u["user_id"] == session["user_id"]), None)
        
        if not user:
            raise InvalidSessionException()

        return UserResponse(**user)
    if authorization.auth_type == "token":
        access_token = authorization.auth_token
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            user = next((u for u in user_db if u["email"] == payload.get("sub")), None)
            if not user:
                raise InvalidTokenException()
            return UserResponse(**user)
        except jwt.ExpiredSignatureError:
            raise InvalidTokenException()
        except jwt.InvalidTokenError:
            raise InvalidTokenException()
