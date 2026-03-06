"""Exceptions for Ctrack Crystal API client."""


class ClientBaseException(Exception):
    default_status_code: int = None

    def __init__(self, message: str, error: Exception = None, status_code: int = None):
        self.status_code = status_code if status_code is not None else self.default_status_code
        self.message = message
        self.error = error
        super().__init__(message)

    def __str__(self):
        return f"{self.status_code}: {self.message}, Error: {self.error}"


class TooManyRequestsException(ClientBaseException):
    default_status_code = 429


class UnauthorizedException(ClientBaseException):
    default_status_code = 401


class ForbiddenException(ClientBaseException):
    default_status_code = 403


class InternalServerException(ClientBaseException):
    default_status_code = 500


class ReadTimeoutException(ClientBaseException):
    """Raised on httpx.ReadTimeout; treated as retriable like 5xx."""
    default_status_code = None
