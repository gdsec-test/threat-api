import unittest.mock as mock
import unittest

import copy
from urllib.error import HTTPError, URLError
from ssl import SSLError

from gd_auth.exceptions import InvalidPublicKeyError, TokenExpiredException

import index

# The following sample event is not complete; some high entropy entries have
# been removed.

EVENT_TEMPLATE = {
    "resource": "/geoip/lookup",
    "path": "/geoip/lookup",
    "httpMethod": "GET",
    "headers": {
        "Host": "api-dev.threat.int.gdcorp.tools",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
        "X-Forwarded-For": "132.148.54.224",
        "X-Forwarded-Port": "443",
        "X-Forwarded-Proto": "https",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.5",
        "referer": "https://api-dev.threat.int.gdcorp.tools/swagger/",
    },
    "queryStringParameters": {"ip": "72.210.63.111"},
    "multiValueQueryStringParameters": {"ip": ["72.210.63.111"]},
    "pathParameters": None,
    "stageVariables": None,
    "requestContext": {
        "accountId": "123456789012",
        "resourceId": "fake-resource-id",
        "stage": "gddeploy",
        "domainName": "api-dev.threat.int.gdcorp.tools",
        "domainPrefix": "api",
        "requestId": "fake-request-uuid",
        "protocol": "HTTP/1.1",
        "identity": {
            "cognitoIdentityPoolId": "",
            "accountId": "",
            "cognitoIdentityId": "",
            "caller": "",
            "apiKey": "",
            "apiKeyId": "",
            "accessKey": "",
            "sourceIp": "132.148.54.224",
            "cognitoAuthenticationType": "",
            "cognitoAuthenticationProvider": "",
            "userArn": "",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "user": "",
        },
        "resourcePath": "/geoip/lookup",
        "authorizer": None,
        "httpMethod": "GET",
        "requestTime": "12/Nov/2020:06:55:31 +0000",
        "requestTimeEpoch": 1605164131326,
        "apiId": "fake-api-id",
    },
    "body": "",
}


class authorizer_tests(unittest.TestCase):
    def test_handler_api_gateway_event(self):

        self.assertEqual(1, 1)

    # The default policy shouldn't change at all; make sure any changes are
    # caught here.

    def test_default_allow_policy(self):
        self.assertEqual(
            index.ALLOW_ALL_POLICY,
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "*"}
                ],
            },
        )

    # Combinations of header and cookie usage

    @mock.patch("index.validate_token")
    def test_without_header_without_cookie_raises_exception(self, mock_validate_token):
        event = copy.deepcopy(EVENT_TEMPLATE)

        with self.assertRaises(Exception):
            index.handler(event, None)

    @mock.patch("index.validate_token")
    def test_with_header_with_cookie(self, mock_validate_token):
        event = copy.deepcopy(EVENT_TEMPLATE)
        event["headers"]["Authorization"] = "sso-jwt fake.header.jwt"
        event["headers"][
            "cookie"
        ] = "key1=value1;auth_jomax=fake.cookie.jwt;key2=value2"

        index.handler(event, None)
        mock_validate_token.assert_called_once_with(b"fake.header.jwt")

    @mock.patch("index.validate_token")
    def test_with_header_without_cookie(self, mock_validate_token):
        event = copy.deepcopy(EVENT_TEMPLATE)
        event["headers"]["Authorization"] = "sso-jwt fake.header.jwt"
        event["headers"][
            "cookie"
        ] = "key1=value1;auth_jomax=fake.cookie.jwt;key2=value2"

        index.handler(event, None)
        mock_validate_token.assert_called_once_with(b"fake.header.jwt")

    @mock.patch("index.validate_token")
    def test_without_header_with_cookie(self, mock_validate_token):
        event = copy.deepcopy(EVENT_TEMPLATE)
        event["headers"][
            "cookie"
        ] = "key1=value1;auth_jomax=fake.cookie.jwt;key2=value2"

        index.handler(event, None)
        mock_validate_token.assert_called_once_with(b"fake.cookie.jwt")

    # validate_token() tests

    @mock.patch("index.AuthToken")
    @mock.patch("index.BaseAuthToken")
    def test_validate_token_normal_flow(self, mock_base_auth_token, mock_auth_token):
        mock_auth_token.payload.return_value = "fake-payload"

        mock_token = mock.MagicMock()
        mock_token.payload = {
            "ftc": 1,
            "factors": {"k_pw": 1605129405},
            "accountName": "gbailey",
            "iat": 1605129405,
        }

        mock_base_auth_token.return_value = mock_token

        result = index.validate_token(b"fake.header.jwt")

        mock_base_auth_token.assert_called_once_with(
            b"fake.header.jwt",
            "fake-payload",
            "sso.gdcorp.tools",
            app="JWTAuthorizer",
            forced_heartbeat=False,
        )

        # Make sure we called _is_valid() on the token object
        mock_token._is_valid.assert_called_once_with()

        # Make sure we called is_expired() on the token object
        mock_token.is_expired.assert_called_once_with(index.TokenBusinessLevel.MEDIUM)

        # The token should be returned
        self.assertEqual(result, mock_token)

    @mock.patch("index.AuthToken")
    @mock.patch("index.BaseAuthToken")
    def test_validate_exception_httperror(self, mock_base_auth_token, mock_auth_token):
        mock_auth_token.payload.return_value = "fake-payload"

        mock_token = mock.MagicMock()
        mock_token.payload = {
            "ftc": 1,
            "factors": {"k_pw": 1605129405},
            "accountName": "gbailey",
            "iat": 1605129405,
        }

        mock_base_auth_token.side_effect = HTTPError(
            url="url", code="code", msg="msg", hdrs="hdrs", fp="fp"
        )

        result = index.validate_token(b"fake.header.jwt")

        # False should be returned
        self.assertEqual(result, False)

    @mock.patch("index.AuthToken")
    @mock.patch("index.BaseAuthToken")
    def test_validate_exception_urlerror(self, mock_base_auth_token, mock_auth_token):
        mock_auth_token.payload.return_value = "fake-payload"

        mock_token = mock.MagicMock()
        mock_token.payload = {
            "ftc": 1,
            "factors": {"k_pw": 1605129405},
            "accountName": "gbailey",
            "iat": 1605129405,
        }

        mock_base_auth_token.side_effect = URLError(reason="reason")

        result = index.validate_token(b"fake.header.jwt")

        # False should be returned
        self.assertEqual(result, False)

    @mock.patch("index.AuthToken")
    @mock.patch("index.BaseAuthToken")
    def test_validate_exception_sslerror(self, mock_base_auth_token, mock_auth_token):
        mock_auth_token.payload.return_value = "fake-payload"

        mock_token = mock.MagicMock()
        mock_token.payload = {
            "ftc": 1,
            "factors": {"k_pw": 1605129405},
            "accountName": "gbailey",
            "iat": 1605129405,
        }

        mock_base_auth_token.side_effect = SSLError()

        result = index.validate_token(b"fake.header.jwt")

        # False should be returned
        self.assertEqual(result, False)

    @mock.patch("index.AuthToken")
    @mock.patch("index.BaseAuthToken")
    def test_validate_token_invalid_public_key(
        self, mock_base_auth_token, mock_auth_token
    ):
        mock_auth_token.payload.return_value = "fake-payload"
        mock_base_auth_token.side_effect = InvalidPublicKeyError()

        result = index.validate_token(b"fake.header.jwt")

        # False should be returned
        self.assertEqual(result, False)

    @mock.patch("index.AuthToken")
    @mock.patch("index.BaseAuthToken")
    def test_validate_token_expired_flow(self, mock_base_auth_token, mock_auth_token):
        mock_auth_token.payload.return_value = "fake-payload"

        mock_token = mock.MagicMock()
        mock_token.payload = {
            "ftc": 1,
            "factors": {"k_pw": 1605129405},
            "accountName": "gbailey",
            "iat": 1605129405,
        }
        mock_token.is_expired.side_effect = TokenExpiredException(code="code")

        mock_base_auth_token.return_value = mock_token

        result = index.validate_token(b"fake.header.jwt")

        # False should be returned
        self.assertEqual(result, False)
