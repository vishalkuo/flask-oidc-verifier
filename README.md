# Flask OIDC Verifier

[![PyPI version](https://badge.fury.io/py/flask-oidc-verifier.svg)](https://badge.fury.io/py/flask-oidc-verifier)

Implements implicit OIDC verification for Flask, similar to [drf-oidc-auth](https://github.com/ByteInternet/drf-oidc-auth) in Django.

## Quickstart

Assumptions: tokens are passed via headers of the form `Authorization: Bearer $YOUR_TOKEN`. These can be changed in the settings

1. Install with `pip install flask-oidc-verifier`
2. Add the following to your flask config (at a minimum, see the Config section for more options). Replace the values with relevant config values:

```python
   class Config():
   ...
   OIDC_ENDPOINT = "https://my.oidc.endpoint"
   OIDC_AUDIENCES = ("MY_AUDIENCES", )
   ...

```

3. Initialize the authentication provider:

```python
from flask import Flask
from flask_oidc_verifier.decorators import JWTVerification
from typing import Dict, Any


app = Flask(__name__)


# Define a callback for what to do with the verified JWT contents
def on_verified(d: Dict[Any, Any]) -> None:
    # get_or_create_user
    ...

auth = auth.init_app(app, on_verified=on_verified)
```

4. Use as a decorator:

```python
@app.route("/protected/<path:filename>")
@auth.jwt_required
def protected_file(filename: str) -> None:
    return send_from_directory("protected", filename)
```

## Config

TODO
