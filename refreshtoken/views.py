from calendar import timegm
from datetime import datetime

from django.conf import settings
from django.utils.translation import ugettext as _
from rest_framework import exceptions, generics, status, viewsets
from rest_framework.decorators import detail_route
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings

from .models import RefreshToken
from .authentication import RefreshTokenAuthentication
from .serializers import DelegateJSONWebTokenSerializer, RefreshTokenSerializer

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER


class DelegateJSONWebToken(generics.CreateAPIView):
    """
    API View that checks the veracity of a refresh token, returning a JWT if it
    is valid.
    """
    permission_classes = [AllowAny]
    authentication_classes = [RefreshTokenAuthentication]
    serializer_class = DelegateJSONWebTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        if request.user != user:
            raise exceptions.AuthenticationFailed(
                _('Invalid auth credentials.'))

        if not user.is_active:
            raise exceptions.AuthenticationFailed(
                _('User inactive or deleted.'))

        payload = jwt_payload_handler(user)
        if api_settings.JWT_ALLOW_REFRESH:
            payload['orig_iat'] = timegm(datetime.utcnow().utctimetuple())
        token = jwt_encode_handler(payload)

        response_data = jwt_response_payload_handler(token, user, request)
        response = Response(response_data, status=status.HTTP_200_OK)

        if api_settings.JWT_AUTH_COOKIE:
            domain = request.META['HTTP_HOST']  # Get current domain
            expiration = (datetime.utcnow() + settings.JWT_COOKIE_EXPIRATION_DELTA)
            response.set_signed_cookie(
                api_settings.JWT_AUTH_COOKIE, token, expires=expiration,
                max_age=expiration, secure=True, httponly=True,
                domain=domain
            )

        return response


class RefreshTokenViewSet(viewsets.ModelViewSet):
    """
    API View that will Create/Delete/List `RefreshToken`.

    https://auth0.com/docs/refresh-token
    """
    serializer_class = RefreshTokenSerializer
    queryset = RefreshToken.objects.all()
    lookup_field = 'key'

    def get_queryset(self):
        queryset = super(RefreshTokenViewSet, self).get_queryset()
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return queryset
        return queryset.filter(user__pk=user.pk)

    @detail_route(methods=['post'])
    def revoke(self, request, key=None):
        obj = self.get_object()
        new_rt = obj.revoke()
        serializer = self.get_serializer(new_rt)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


delegate_jwt_token = DelegateJSONWebToken.as_view()
