from flask_oidc_verifier.decorators import JWTVerification, AuthenticationFailed
from tests.mocks import MockResponse
from typing import Any, Callable
import requests
import pytest
from freezegun import freeze_time
from datetime import datetime
from flask_oidc_verifier.caches import Cache


OIDCConfig = {"jwks_uri": "some_jwks_uri", "issuer": "some_issuer"}


def test_validate_claims_invalid_issuer(monkeypatch: Any, default_cache: Cache) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(
        oidc_leeway=100,
        oidc_endpoint="http://dummy/endpoint.com",
        oidc_audiences=("test",),
        cache=default_cache,
    )
    with pytest.raises(AuthenticationFailed):
        verification.validate_claims(
            {"iss": "foo", "aud": "bar", "exp": 1, "nbf": 2, "iat": 0}
        )


def test_validate_claims_invalid_aud(monkeypatch: Any, default_cache: Cache,) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(
        oidc_leeway=100,
        oidc_endpoint="http://dummy/endpoint.com",
        oidc_audiences=(audience,),
        cache=default_cache,
    )
    with pytest.raises(AuthenticationFailed):
        verification.validate_claims(
            {"iss": OIDCConfig["issuer"], "aud": "foo", "exp": 1, "nbf": 2, "iat": 0}
        )


def test_validate_claims_token_already_exp(
    monkeypatch: Any, default_cache: Cache
) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(
        oidc_leeway=100,
        oidc_endpoint="http://dummy/endpoint.com",
        oidc_audiences=(audience,),
        cache=default_cache,
    )
    with pytest.raises(AuthenticationFailed), freeze_time(datetime(2020, 1, 1)):
        verification.validate_claims(
            {"iss": OIDCConfig["issuer"], "aud": audience, "exp": 1, "nbf": 2, "iat": 0}
        )


def test_validate_claims_token_iat(monkeypatch: Any, default_cache: Cache) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(
        oidc_leeway=100,
        oidc_endpoint="http://dummy/endpoint.com",
        oidc_audiences=(audience,),
        cache=default_cache,
        verify_iat=True,
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


def test_validate_claims_token_nbf(monkeypatch: Any, default_cache: Cache) -> None:
    def mock_get(*args: Any, **kwargs: Any) -> MockResponse:
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(
        oidc_leeway=100,
        oidc_endpoint="http://dummy/endpoint.com",
        oidc_audiences=(audience,),
        cache=default_cache,
    )
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


def test_validate_claims_token(monkeypatch: Any, default_cache: Cache) -> None:
    call_count = 0

    def mock_get(args: Any, **kwargs: Any) -> MockResponse:
        nonlocal call_count
        call_count += 1
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(
        oidc_leeway=100,
        oidc_endpoint="http://dummy/endpoint.com",
        oidc_audiences=(audience,),
        cache=default_cache,
    )
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

    assert call_count == 1


def test_cache_with_redis(
    monkeypatch: Any, redis_cache: Cache, reset_redis: Callable[[], None]
) -> None:
    call_count = 0

    reset_redis()

    def mock_get(args: Any, **kwargs: Any) -> MockResponse:
        nonlocal call_count
        call_count += 1
        return MockResponse(OIDCConfig)

    audience = "some_aud"
    monkeypatch.setattr(requests, "get", mock_get)
    verification = JWTVerification(
        oidc_leeway=100,
        oidc_endpoint="http://dummy/endpoint.com",
        oidc_audiences=(audience,),
        cache=redis_cache,
    )
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

    assert call_count == 1
