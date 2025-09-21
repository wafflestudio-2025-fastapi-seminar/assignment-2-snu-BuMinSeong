from fastapi import FastAPI, status, Request
from fastapi.exceptions import RequestValidationError
from fastapi.response import JSONResponse

from tests.util import get_all_src_py_files_hash
from src.api import api_router

from src.users.schemas import CreateUserRequest, UserResponse
from src.users.errors import *

app = FastAPI()

app.include_router(api_router)

@app.exception_handler(RequestValidationError)
def handle_request_validation_error(request, exc):
    pass

@app.get("/health")
def health_check():
    # 서버 정상 배포 여부를 확인하기 위한 엔드포인트입니다.
    # 본 코드는 수정하지 말아주세요!
    hash = get_all_src_py_files_hash()
    return {
        "status": "ok",
        "hash": hash
    }

user_db = {}

# /api/users 엔드포인트
@app.post("/api/users/", status_code=status.HTTP_200_OK)
def create_user(request: CreateUserRequest) -> UserResponse:
    user_id = len(user_db) + 1
    user_db[user_id] = request.model_dump()

    # check is there any repeated Email
    for user in user_db:
        if user["email"] == request.email:
            raise InvalidEmailException()

    return UserResponse(
        user_id=user_id,
        name=request.name,
        email=request.email,
        password=request.password,
        phone_number=request.phone_number,
        height=request.height,
        bio=request.bio
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    custom_exc = MissingValueException()
    return JSONResponse(
        status_code=custom_exc.status_code,
        content={
            "error_code": custom_exc.error_code,
            "error_message": custom_exc.error_message
        }
    )