from django.utils.encoding import smart_text
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext as _

import jwt
from rest_framework import exceptions
from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.utils import jwt_get_secret_key
from rest_framework.authentication import get_authorization_header
from rest_framework_jwt.authentication import JSONWebTokenAuthentication


def jwt_decode_handler(token):
    """
    Disable token signature verification.

    This allows us to verify expired tokens without getting a
    jwt.InvalidToken exception.
    """
    options = {
        'verify_exp': False
    }
    # get user from token, BEFORE verification, to get user secret key
    unverified_payload = jwt.decode(token, None, False)
    secret_key = jwt_get_secret_key(unverified_payload)
    return jwt.decode(
        token,
        api_settings.JWT_PUBLIC_KEY or secret_key,
        api_settings.JWT_VERIFY,
        options=options,
        leeway=api_settings.JWT_LEEWAY,
        audience=api_settings.JWT_AUDIENCE,
        issuer=api_settings.JWT_ISSUER,
        algorithms=[api_settings.JWT_ALGORITHM]
    )


class RefreshTokenAuthentication(JSONWebTokenAuthentication):
    """
    Extends JSONWebTokenAuthentication to:

    Allow users authenticate with expired JWT's
    """

    def get_jwt_value(self, request):
        """Get the JWT from the signed cookie or request header."""
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth:
            if api_settings.JWT_AUTH_COOKIE:
                return request.get_signed_cookie(
                    api_settings.JWT_AUTH_COOKIE, default=None
                )
            return None

        if smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string '
                    'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = jwt_decode_handler(jwt_value)
        except jwt.DecodeError:
            msg = _('Error decoding signature.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()

        user = self.authenticate_credentials(payload)

        return user, payload

    def jwt_get_user_uuid_from_payload(self, payload):
        """Get the user's uuid from the JWT payload."""

        return payload.get('uuid')

    def authenticate_credentials(self, payload):
        """Returns an active user that matches the JWT payload's user uuid."""
        User = get_user_model()
        user_uuid = self.jwt_get_user_uuid_from_payload(payload)

        if not user_uuid:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            user = User.objects.get(uuid=user_uuid)
        except User.DoesNotExist:
            msg = _('User Does not Exist.')
            raise exceptions.AuthenticationFailed(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise exceptions.AuthenticationFailed(msg)

        return user
