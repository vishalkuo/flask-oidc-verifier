from typing import Any, Dict


class MockResponse:
    def __init__(self, return_val: Dict[Any, Any]) -> None:
        self.return_val = return_val

    def json(self) -> Dict[Any, Any]:
        return self.return_val
