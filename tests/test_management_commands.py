"""Test django management commands."""

from django.contrib.auth import get_user_model
from django.core.management import call_command


def test_command_generate_refresh_tokens(alice, admin_user):
    " Test refresh token generation command."

    # Users shouldn't have any refresh token.
    refresh_tokens_queryset = get_user_model().objects.filter(
        refresh_tokens__isnull=True
    )
    assert refresh_tokens_queryset.count() == 2

    call_command('generate_refresh_tokens', *[], **{})

    # All users should have refresh tokens.
    assert refresh_tokens_queryset.count() == 0
