from typing import Any, Callable, TypeVar

from typing_extensions import Protocol

FuncType = Callable[..., Any]  # type: ignore
ReturnT = TypeVar("ReturnT", bound=FuncType)


class VerificationProtocol(Protocol):
    def verify_oidc(self, view_func: ReturnT) -> ReturnT:
        raise ValueError("Not Implemented")
