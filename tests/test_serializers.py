import unittest

from distutils.version import StrictVersion
from functools import wraps

import rest_framework
from django.conf.urls import patterns, url, include
from django.test import TestCase
from rest_framework.exceptions import ValidationError
from rest_framework.reverse import reverse

from rest_framework_jwt.compat import get_user_model
from rest_framework_jwt.serializers import JSONWebTokenSerializer, \
    SocialTokenSerializer
from rest_framework_jwt import utils

from mock import patch, MagicMock
from social.apps.django_app.views import NAMESPACE

User = get_user_model()

drf2 = rest_framework.VERSION < StrictVersion('3.0.0')
drf3 = rest_framework.VERSION >= StrictVersion('3.0.0')


class JSONWebTokenSerializerTests(TestCase):
    def setUp(self):
        self.email = 'jpueblo@example.com'
        self.username = 'jpueblo'
        self.password = 'password'
        self.user = User.objects.create_user(
            self.username, self.email, self.password)

        self.data = {
            'username': self.username,
            'password': self.password
        }

    @unittest.skipUnless(drf2, 'not supported in this version')
    def test_empty_drf2(self):
        serializer = JSONWebTokenSerializer()
        expected = {
            'username': ''
        }

        self.assertEqual(serializer.data, expected)

    @unittest.skipUnless(drf3, 'not supported in this version')
    def test_empty_drf3(self):
        serializer = JSONWebTokenSerializer()
        expected = {
            'username': '',
            'password': ''
        }

        self.assertEqual(serializer.data, expected)

    def test_create(self):
        serializer = JSONWebTokenSerializer(data=self.data)
        is_valid = serializer.is_valid()

        token = serializer.object['token']
        decoded_payload = utils.jwt_decode_handler(token)

        self.assertTrue(is_valid)
        self.assertEqual(decoded_payload['username'], self.username)

    def test_invalid_credentials(self):
        self.data['password'] = 'wrong'
        serializer = JSONWebTokenSerializer(data=self.data)
        is_valid = serializer.is_valid()

        expected_error = {
            'non_field_errors': ['Unable to login with provided credentials.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)

    def test_disabled_user(self):
        self.user.is_active = False
        self.user.save()

        serializer = JSONWebTokenSerializer(data=self.data)
        is_valid = serializer.is_valid()

        expected_error = {
            'non_field_errors': ['User account is disabled.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)

    def test_required_fields(self):
        serializer = JSONWebTokenSerializer(data={})
        is_valid = serializer.is_valid()

        expected_error = {
            'username': ['This field is required.'],
            'password': ['This field is required.']
        }

        self.assertFalse(is_valid)
        self.assertEqual(serializer.errors, expected_error)

test_backend = 'backend'
test_code = 'code'
test_username = "test user"
test_email = "test@test.com"


def patch_backend(f):
    @patch('rest_framework_jwt.serializers.load_strategy')
    @patch('rest_framework_jwt.serializers.load_backend')
    @wraps(f)
    def decorated(*args, **kwargs):
        arg_array = list(args)
        load_strategy_mock = arg_array.pop()
        load_backend_mock = arg_array.pop()
        load_strategy_mock.return_value = "test strategy"
        backend_mock = MagicMock()
        load_backend_mock.return_value = backend_mock
        backend_mock.auth_complete.return_value = \
            User(pk=1, username=test_username, email=test_email)
        r = f(*arg_array, **kwargs)
        load_backend_mock.assert_called_once_with(
            "test strategy",
            test_backend,
            reverse(NAMESPACE + ":complete", args=(test_backend,))
        )
        return r
    return decorated


urlpatterns = patterns(
    '',
    url(r'^social-auth/',
        include('social.apps.django_app.urls', namespace=NAMESPACE))
)


class SocialTokenSerializerTestCase(TestCase):

    urls = 'tests.test_serializers'

    def test_login(self):
        serializer = SocialTokenSerializer(
            data={
                'backend': test_backend,
                'code': test_code
            },
            context={
                'request': {}
            }
        )

        @patch_backend
        def is_valid_call():
            return serializer.is_valid()

        is_valid = is_valid_call()

        token = serializer.object['token']
        decoded_payload = utils.jwt_decode_handler(token)

        self.assertTrue(is_valid)
        self.assertEqual(decoded_payload['username'], test_username)

    def test_required_fields(self):
        serializer = SocialTokenSerializer(data={})

        @patch_backend
        def is_valid_call():
            return serializer.is_valid(raise_exception=True)

        self.assertRaises(ValidationError, is_valid_call)

        expected_error = {
            'backend': ['This field is required.'],
            'code': ['This field is required.']
        }

        self.assertEqual(serializer.errors, expected_error)
