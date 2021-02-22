from typing import Any, Dict, Optional


class MockResponse:
    def __init__(self, return_val: Dict[Any, Any], exc: Optional[Any] = None) -> None:
        self.return_val = return_val
        self.exc = exc

    def json(self) -> Dict[Any, Any]:
        return self.return_val

    def raise_for_status(self) -> None:
        if self.exc is not None:
            raise self.exc
