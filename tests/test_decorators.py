from flask_oidc_verifier.decorators import JWTVerification, AuthenticationFailed
from tests.mocks import MockResponse
from typing import Any
import requests
import pytest
from freezegun import freeze_time
from datetime import datetime


OIDCConfig = {"jwks_uri": "some_jwks_uri", "issuer": "some_issuer"}


def test_validate_claims_invalid_issuer(monkeypatch: Any) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(100, "http://dummy/endpoint.com", ("test",))
    with pytest.raises(AuthenticationFailed):
        verification.validate_claims(
            {"iss": "foo", "aud": "bar", "exp": 1, "nbf": 2, "iat": 0}
        )


def test_validate_claims_invalid_aud(monkeypatch: Any) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(100, "http://dummy/endpoint.com", (audience,))
    with pytest.raises(AuthenticationFailed):
        verification.validate_claims(
            {"iss": OIDCConfig["issuer"], "aud": "foo", "exp": 1, "nbf": 2, "iat": 0}
        )


def test_validate_claims_token_already_exp(monkeypatch: Any) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(100, "http://dummy/endpoint.com", (audience,))
    with pytest.raises(AuthenticationFailed), freeze_time(datetime(2020, 1, 1)):
        verification.validate_claims(
            {"iss": OIDCConfig["issuer"], "aud": audience, "exp": 1, "nbf": 2, "iat": 0}
        )


def test_validate_claims_token_iat(monkeypatch: Any) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(
        0, "http://dummy/endpoint.com", (audience,), verify_iat=True
    )
    t = datetime(2020, 1, 1)
    with pytest.raises(AuthenticationFailed), freeze_time(t):
        verification.validate_claims(
            {
                "iss": OIDCConfig["issuer"],
                "aud": audience,
                "exp": int(t.strftime("%s")),
                "nbf": int(datetime(2019, 12, 12).strftime("%s")),
                "iat": int(datetime(2019, 12, 30, 23, 59, 59).strftime("%s")),
            }
        )


def test_validate_claims_token_nbf(monkeypatch: Any) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(100, "http://dummy/endpoint.com", (audience,))
    t = datetime(2020, 1, 1)
    with pytest.raises(AuthenticationFailed), freeze_time(t):
        verification.validate_claims(
            {
                "iss": OIDCConfig["issuer"],
                "aud": audience,
                "exp": int(t.strftime("%s")),
                "nbf": int(datetime(2020, 2, 2).strftime("%s")),
                "iat": 0,
            }
        )


def test_validate_claims_token(monkeypatch: Any) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(100, "http://dummy/endpoint.com", (audience,))
    t = datetime(2020, 1, 1)
    with freeze_time(t):
        verification.validate_claims(
            {
                "iss": OIDCConfig["issuer"],
                "aud": audience,
                "exp": int(t.strftime("%s")),
                "nbf": 0,
                "iat": int(datetime(2020, 2, 2).strftime("%s")),
            }
        )
