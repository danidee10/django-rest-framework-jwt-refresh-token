<div class="badges">
    <a href="https://travis-ci.org/lock8/django-rest-framework-jwt-refresh-token">
        <img src="https://travis-ci.org/lock8/django-rest-framework-jwt-refresh-token.svg?branch=master">
    </a>
    <a href="https://pypi.python.org/pypi/djangorestframework-jwt-refresh-token">
        <img src="https://img.shields.io/pypi/v/djangorestframework-jwt-refresh-token.svg">
    </a>
    <a href="https://codecov.io/github/lock8/django-rest-framework-jwt-refresh-token?branch=master">
      <img src="https://codecov.io/github/lock8/django-rest-framework-jwt-refresh-token/coverage.svg?branch=master">
    </a>
</div>

---

# Long Running Refresh Token for REST framework JWT Auth

Long running refresh token support for JSON Web Token Authentication support for Django REST Framework

---

## Overview

This package provides a plugin that allow JWT to be re-issued for one that owns refresh token stored on database.


## Requirements

- Python (3.4, 3.5)
- Django (1.8, 1.9)
- Django REST Framework (3.3)

## Installation

Install using `pip`...

```
$ pip install djangorestframework-jwt-refresh-token
```

## Long Running Refresh Token

This allows for a client to request refresh tokens. These refresh tokens do not expire.
They can be revoked (deleted). When a JWT has expired, it's possible to send a request
with the refresh token in the header, and get back a new JWT.

In your `settings.py`, add `refreshtoken` to `INSTALLED_APPS`.

```python
INSTALLED_APPS = [
    ...,
    'refreshtoken',
  ]
}
```

Then run migrate to add the new model.

```bash
python manage.py migrate refreshtoken
```

In your `urls.py` add the following URL route to enable obtaining a token via a POST included the user's username and password.


Configure your urls to add new endpoint

```python
from refreshtoken.routers import router as rt_router

urlpatterns = [
    url(...),
] + rt_router.urls

```

You can include this refresh token in your JWT_RESPONSE_PAYLOAD_HANDLER

```python
def jwt_response_payload_handler(token, user=None, request=None):
    payload = {
        'token': token,
    }

    app = 'test'
    try:
        refresh_token = user.refresh_tokens.get(app=app).key
    except RefreshToken.DoesNotExist:
        refresh_token = None

    payload['refresh_token'] = refresh_token
    return payload
```

Then declare this custom payload_handler in your settings:

```python
JWT_AUTH = {
    ...,
    'JWT_RESPONSE_PAYLOAD_HANDLER': 'path.to.jwt_response_payload_handler',
    ...,
}
```

Then your user can ask a new JWT token as long as the refresh_token exists.

```bash
$ http POST refresh_token=<REFRESH_TOKEN> api_type=app http://localhost:8000/delegate/
```
```json
{"token": "your_jwt_token_...", "refresh_token": "your long running refresh token..."}
```

Like `django-rest-framework-jwt`, It's also possible to pass the `REFRESH_TOKEN` as a cookie. It's recommended to use a Secure/httpOnly cookie so the cookie value can't be read from JavaScript.

If you set `JWT_AUTH_COOKIE` `django-rest-framework-jwt-refresh-token` automatically does that for you.

***Note that the cookies are checked before the request body.***
