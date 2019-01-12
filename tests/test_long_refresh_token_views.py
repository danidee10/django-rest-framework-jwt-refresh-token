from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_jwt import utils

from refreshtoken.models import RefreshToken
from refreshtoken.views import RefreshTokenViewSet

from .urls import urlpatterns  # noqa

try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse


User = get_user_model()


class RefreshTokenTestCase(APITestCase):
    urls = __name__

    def setUp(self):
        self.email = 'jpueblo@example.com'
        self.username = 'jpueblo'
        self.password = 'password'
        self.user = User.objects.create_user(
            self.username, self.email, self.password)
        self.token = RefreshToken.objects.create(user=self.user,
                                                 app='test-app')
        email1 = 'jonny@example.com'
        username1 = 'jonnytestpants'
        password1 = 'password'
        self.user1 = User.objects.create_user(username1, email1, password1)
        self.token1 = RefreshToken.objects.create(user=self.user1,
                                                  app='another-app')

        self.list_url = reverse('refreshtoken-list')
        self.detail_url = reverse(
            'refreshtoken-detail',
            kwargs={'key': self.token.key}
        )
        self.detail_url1 = reverse(
            'refreshtoken-detail',
            kwargs={'key': self.token1.key}
        )
        self.revoke_url = reverse(
            'refreshtoken-revoke',
            kwargs={'key': self.token.key}
        )
        self.delegate_url = reverse('delegate-tokens')
        self.user_admin = User.objects.create_user(
            'adminator', self.email, self.password,
        )
        self.user_admin.is_superuser = True
        self.user_admin.save()

    def test_repr_refresh_token(self):
        print(self.token)

    def test_requires_auth(self):
        response = self.client.get(self.list_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )

        response = self.client.get(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )

        response = self.client.delete(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )

        response = self.client.post(self.list_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )

    def test_get_refresh_token_list_with_admin(self):
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user_admin)))
        response = self.client.get(self.list_url)
        self.assertEqual(len(response.data), 2)

    def test_get_refresh_token_list(self):
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user)))
        response = self.client.get(self.list_url)
        self.assertEqual(len(response.data), 1)
        resp0 = response.data[0]
        self.assertEqual(self.token.key, resp0['key'])

        self.client.force_authenticate(self.user1)
        response = self.client.get(self.list_url)
        self.assertEqual(len(response.data), 1)
        resp0 = response.data[0]
        self.assertEqual(self.token1.key, resp0['key'])

        self.assertEqual(RefreshToken.objects.count(), 2)

    def test_get_refresth_token_detail(self):
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user)))
        response = self.client.get(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
            (response.status_code, response.content)
        )
        response = self.client.get(self.detail_url1)
        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
            (response.status_code, response.content)
        )

    def test_delete_refresth_token(self):
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user)))
        response = self.client.delete(self.detail_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_204_NO_CONTENT,
            (response.status_code, response.content)
        )
        response = self.client.delete(self.detail_url1)
        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
            (response.status_code, response.content)
        )

    def test_revoke_refresh_token(self):
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user)))
        response = self.client.post(self.revoke_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
            (response.status_code, response.content)
        )
        new_rt = self.user.refresh_tokens.get()
        self.assertEqual(
            response.data,
            {'key': new_rt.key,
             'app': new_rt.app,
             'user': self.user.pk,
             'created': new_rt.created.isoformat()[:-6] + 'Z',
             })
        response = self.client.post(self.revoke_url)
        self.assertEqual(
            response.status_code,
            status.HTTP_404_NOT_FOUND,
            (response.status_code, response.content)
        )

    def test_create_refresh_token(self):
        data = {
            'app': 'gandolf'
        }
        self.client.credentials(
            HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
                utils.jwt_payload_handler(self.user)))
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(
            response.status_code,
            status.HTTP_201_CREATED,
            (response.status_code, response.content)
        )
        self.assertEqual(response.data['user'], self.user.pk)
        self.assertEqual(response.data['app'], data['app'])

    def test_delegate_jwt(self):
        data = {
            'client_id': 'gandolf',
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'refresh_token': self.token1.key,
            'api_type': 'app',
        }
        response = self.client.post(self.delegate_url,
                                    data=data,
                                    format='json')
        self.assertEqual(
            response.status_code,
            status.HTTP_200_OK,
            (response.status_code, response.content)
        )
        self.assertIn('token', response.data)

    def test_invalid_body_delegate_jwt(self):
        # refresh token is missing
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'api_type': 'app',
        }
        response = self.client.post(self.delegate_url, data=data,
                                    format='json')
        self.assertEqual(
            response.status_code,
            status.HTTP_400_BAD_REQUEST,
            (response.status_code, response.content)
        )

    def test_delegate_jwti_wrong_token(self):
        data = {
            'client_id': 'gandolf',
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'refresh_token': 'nope',
            'api_type': 'app',
        }
        response = self.client.post(self.delegate_url,
                                    data=data,
                                    format='json')
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )

    def test_delegate_jwti_inactive_user(self):
        data = {
            'client_id': 'gandolf',
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'refresh_token': self.token1.key,
            'api_type': 'app',
        }
        self.user1.is_active = False
        self.user1.save()
        response = self.client.post(self.delegate_url,
                                    data=data,
                                    format='json')
        self.assertEqual(
            response.status_code,
            status.HTTP_401_UNAUTHORIZED,
            (response.status_code, response.content)
        )


def test_get_queryset_with_anon_user():
    class FakeRequest:
        user = AnonymousUser()

    view = RefreshTokenViewSet()
    view.request = FakeRequest
    view.get_queryset()
