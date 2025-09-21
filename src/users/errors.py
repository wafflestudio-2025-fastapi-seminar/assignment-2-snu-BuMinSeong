from common import CustomException

class MissingValueException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422,
            error_code="ERR_001",
            error_message="MISSING VALUE"
        )

class InvalidPasswordException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422,
            error_code="ERR_002",
            error_message="INVALID PASSWORD"
        )

class InvalidPhonenumberException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422,
            error_code="ERR_003",
            error_message="INVALID PHONE NUMBER"
        )

class InvalidBioException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422,
            error_code="ERR_004",
            error_message="BIO TOO LONG"
        )

class invalidEmailException(CustomException):
    def __init__(self):
        super().__init__(
            status_code=422,
            error_code="ERR_005",
            error_message="EMAIL ALREADY EXISTS"
        )