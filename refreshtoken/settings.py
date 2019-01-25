import calendar
import datetime

from django.conf import settings
from rest_framework.settings import APISettings


def days_in_current_year():
    year = datetime.datetime.now().year
    return 366 if calendar.isleap(year) else 365


USER_SETTINGS = getattr(settings, 'JWT_AUTH', None)

DEFAULTS = {
    'JWT_APP_NAME': 'refreshtoken',
    'JWT_REFRESH_TOKEN_EXPIRATION_DELTA':
        datetime.timedelta(days=days_in_current_year()/2)
}

api_settings = APISettings(USER_SETTINGS, DEFAULTS, [])
