import time

import jwt
from argon2 import PasswordHasher
from src.auth.schemas import SECRET_KEY, ALGORITHM


from fastapi import (
    APIRouter,
    Cookie,
    Header,
    status,
)

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import session_db, user_db
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

@user_router.get("/me", status_code=status.HTTP_200_OK)
def get_user_info(sid: str | None = Cookie(None),
                    authorization: str | None = Header(None)) -> UserResponse:
    if not sid and not authorization:
        raise UnauthenticatedException()
    
    if sid:
        session = session_db.get(sid)
        if not session or session.get("exp") <= int(time.time()):
            raise InvalidSessionException()
        user = next((u for u in user_db if u["email"] == session["email"]), None)
        if not user:
            raise InvalidSessionException()
        return UserResponse(**user)
    
    if authorization:
        if not authorization.startswith("Bearer "):
            raise AuthorizationHeaderException()
        
        access_token = authorization.split(" ")[1]
        
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            user = next((u for u in user_db if u["email"] == payload.get("sub")), None)
            if not user:
                raise InvalidTokenException()
            return UserResponse(**user)
        
        except jwt.InvalidTokenError:
            raise InvalidTokenException()