from django.conf import settings
from rest_framework.settings import APISettings


USER_SETTINGS = getattr(settings, 'JWT_AUTH', None)

DEFAULTS = {
    'JWT_APP_NAME': 'refreshtoken',
}

api_settings = APISettings(USER_SETTINGS, DEFAULTS, [])
