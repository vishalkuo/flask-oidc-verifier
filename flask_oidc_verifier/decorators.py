import datetime
from calendar import timegm
from hmac import compare_digest
from os import path
from typing import Any, Callable, List, Optional, Tuple, Union, cast, Dict

import requests
from cachetools import TTLCache
from flask import Request, request
from jwkest import JWKESTException
from jwkest.jwk import KEYS
from jwkest.jws import JWS
from typing_extensions import TypedDict

from flask import Flask
from flask_oidc_verifier.jwt_parser import get_jwt_value
from flask_oidc_verifier.verification import ReturnT, VerificationProtocol
from flask_oidc_verifier.caches import Cache

OIDCConfig = TypedDict("OIDCConfig", {"jwks_uri": str, "issuer": str})
OIDCPayload = TypedDict(
    "OIDCPayload",
    {"iss": str, "aud": Union[List[str], str], "exp": int, "nbf": int, "iat": int},
)


class AuthenticationFailed(Exception):
    pass


class JWTVerification(VerificationProtocol):
    @classmethod
    def init_app(  # type: ignore
        cls,
        app: Flask,
        *,
        on_verified: Optional[Callable[[Dict[str, Any]], None]] = None,
        cache: Optional[Cache] = None,
    ) -> "JWTVerification":
        app.config.setdefault("OIDC_AUTH_HEADER_PREFIX", "Bearer")
        app.config.setdefault("OIDC_AUTH_HEADER", "Authorization")
        app.config.setdefault("OIDC_CACHE_TIMEOUT_S", 60 * 10)
        app.config.setdefault("OIDC_VERIFY_IAT", True)
        app.config.setdefault("OIDC_LEEWAY", 60 * 10)
        if cache is None:
            cache = TTLCache(maxsize=10, ttl=app.config["OIDC_CACHE_TIMEOUT_S"])

        return cls(
            oidc_leeway=app.config["OIDC_LEEWAY"],
            oidc_endpoint=app.config["OIDC_ENDPOINT"],
            oidc_audiences=app.config["OIDC_AUDIENCES"],
            auth_header_prefix=app.config["OIDC_AUTH_HEADER_PREFIX"],
            authorization_header=app.config["OIDC_AUTH_HEADER"],
            verify_iat=app.config["OIDC_VERIFY_IAT"],
            on_verified=on_verified,
            cache=cache,
        )

    def __init__(  # type: ignore
        self,
        *,
        oidc_leeway: int,
        oidc_endpoint: str,
        oidc_audiences: Tuple[str],
        cache: Cache,
        auth_header_prefix: str = "Bearer",
        authorization_header: str = "Authorization",
        verify_iat: bool = True,
        on_verified: Optional[Callable[[Any], None]] = None,
    ) -> None:
        self.oidc_leeway = oidc_leeway
        self.oidc_endpoint = oidc_endpoint
        self.oidc_audiences = oidc_audiences
        self.on_verified = on_verified
        self.config_cache = cache
        self.auth_header_prefix = auth_header_prefix
        self.authorization_header = authorization_header
        self.verify_iat = verify_iat

    def jwt_required(self, view_func: ReturnT) -> ReturnT:
        def wrapper(*args: Any, **kwargs: Any) -> Any:  # type: ignore
            try:
                payload = self.authenticate(request)
            except AuthenticationFailed as e:
                return {"error": str(e)}, 401
            if self.on_verified is not None:
                self.on_verified(payload)
            return view_func(*args, **kwargs)

        return cast(ReturnT, wrapper)

    @property
    def oidc_config(self) -> OIDCConfig:
        config = cast(
            Optional[OIDCConfig],
            self.config_cache.get("flask-oidc-config", default=None),
        )
        if config is not None:
            return config
        result = requests.get(
            path.join(self.oidc_endpoint, ".well-known/openid-configuration")
        ).json()
        self.config_cache["flask-oidc-config"] = result
        return cast(OIDCConfig, result)

    def authenticate(self, r: Request) -> OIDCPayload:
        jwt_value = get_jwt_value(
            request,
            self.authorization_header,
            self.auth_header_prefix,
            AuthenticationFailed,
        )
        decoded = self.decode_jwt(jwt_value)
        self.validate_claims(decoded)
        return decoded

    def decode_jwt(self, jwt_value: str) -> OIDCPayload:
        keys = self.jwks()
        try:
            id_token = JWS().verify_compact(jwt_value, keys=keys)
        except (JWKESTException, ValueError):
            raise AuthenticationFailed(
                "Invalid Authorization header. JWT Signature verification failed."
            )

        return cast(OIDCPayload, id_token)

    def jwks(self) -> KEYS:  # type: ignore
        keys = KEYS()
        keys.load_jwks(self.jwks_data())
        return keys

    def jwks_data(self) -> str:
        result = cast(
            Optional[str], self.config_cache.get("flask-oidc-jwks-data", None)
        )
        if result is not None:
            return result
        r = requests.get(self.oidc_config["jwks_uri"], allow_redirects=True)
        r.raise_for_status()
        self.config_cache["flask-oidc-jwks-data"] = r.text
        return r.text

    def validate_claims(self, id_token: OIDCPayload) -> None:
        if isinstance(id_token["aud"], str):
            # Support for multiple audiences
            id_token["aud"] = [id_token["aud"]]

        if not compare_digest(id_token["iss"], self.oidc_config["issuer"]):
            raise AuthenticationFailed(
                "Invalid Authorization header. Invalid JWT issuer."
            )

        if not any(aud in self.oidc_audiences for aud in id_token.get("aud", [])):
            raise AuthenticationFailed(
                "Invalid Authorization header. Invalid JWT audience."
            )

        if len(id_token["aud"]) > 1 and "azp" not in id_token:
            raise AuthenticationFailed(
                "Invalid Authorization header. Missing JWT authorized party."
            )

        utc_timestamp = timegm(datetime.datetime.utcnow().utctimetuple())
        if utc_timestamp > id_token.get("exp", 0):
            raise AuthenticationFailed("Invalid Authorization header. JWT has expired.")

        if (
            self.verify_iat
            and utc_timestamp > id_token.get("iat", 0) + self.oidc_leeway
        ):
            raise AuthenticationFailed("Invalid Authorization header. JWT too old.")

        if "nbf" in id_token and utc_timestamp < id_token["nbf"]:
            raise AuthenticationFailed(
                "Invalid Authorization header. JWT not yet valid."
            )
