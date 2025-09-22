from fastapi import FastAPI, status, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from tests.util import get_all_src_py_files_hash
from src.api import api_router

from src.users.schemas import CreateUserRequest, UserResponse
from src.users.errors import *

app = FastAPI()

app.include_router(api_router)

# Handles Missing Value Exception
@app.exception_handler(RequestValidationError)
def handle_request_validation_error(request: Request, exc: RequestValidationError):
    errors = exc.errors()

    only_missing = all(error["type"] == "missing" or error["msg"] == "field required" for error in errors)

    if only_missing:
        return JSONResponse(
            status_code=401,
            content={
                "error_code": "ERR_001",
                "error_message": "MISSING VALUE"
            }
        )
    return JSONResponse(
        status_code=422,
        content={"detail": errors}
    )

@app.get("/health")
def health_check():
    # 서버 정상 배포 여부를 확인하기 위한 엔드포인트입니다.
    # 본 코드는 수정하지 말아주세요!
    hash = get_all_src_py_files_hash()
    return {
        "status": "ok",
        "hash": hash
    }