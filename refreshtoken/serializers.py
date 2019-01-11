from django.utils.translation import ugettext as _
from rest_framework import exceptions, serializers

from .models import RefreshToken


class RefreshTokenSerializer(serializers.ModelSerializer):
    """
    Serializer for refresh tokens (Not RefreshJWTToken)
    """

    user = serializers.PrimaryKeyRelatedField(
        required=False,
        read_only=True,
        default=serializers.CurrentUserDefault())

    class Meta:
        model = RefreshToken
        fields = ('key', 'user', 'created', 'app')
        read_only_fields = ('key', 'created')

    def create(self, validated_data):
        """Override ``create`` to provide a user via request.user by default.

        This is required since the read_only ``user`` field is not included by
        default anymore since
        https://github.com/encode/django-rest-framework/pull/5886.
        """
        if 'user' not in validated_data:
            validated_data['user'] = self.context['request'].user
        return super(RefreshTokenSerializer, self).create(validated_data)


class DelegateJSONWebTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        """Check if a valid, non-expired token exists for the user."""
        refresh_token = attrs['refresh_token']
        try:
            token = RefreshToken.objects.select_related('user').get(
                key=refresh_token)
        except RefreshToken.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid Refresh token.'))
        attrs['user'] = token.user

        return attrs
