<<<<<<< HEAD
import datetime

=======
>>>>>>> master
from django.conf import settings
from rest_framework.settings import APISettings


USER_SETTINGS = getattr(settings, 'JWT_AUTH', None)

DEFAULTS = {
    'JWT_APP_NAME': 'refreshtoken',
    'JWT_REFRESH_COOKIE': 'refresh_token',
    'JWT_REFRESH_COOKIE_EXPIRATION_DELTA': datetime.timedelta(seconds=300)
}

api_settings = APISettings(USER_SETTINGS, DEFAULTS, [])
