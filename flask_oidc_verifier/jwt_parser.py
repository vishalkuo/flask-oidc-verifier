from hmac import compare_digest
from typing import Type

from flask import Request


def get_jwt_value(
    r: Request, auth_header: str, auth_header_prefix: str, exc: Type[Exception]
) -> str:
    auth = r.headers.get(auth_header)
    if not auth:
        raise exc("No authorization header provided")
    auth_arr = auth.split(" ")
    if not compare_digest(auth_arr[0].lower(), auth_header_prefix.lower()):
        raise exc("Invalid authorization header.")

    if len(auth_arr) == 1:
        raise exc("Invalid authorization header. No credentials provided")
    elif len(auth_arr) > 2:
        raise exc("Invalid authorization header.")
    return auth_arr[1]
