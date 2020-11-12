#!/usr/bin/env python3

# Lambda authorizer for Jomax (employee) JWTs
# Based on: lambda/jwt_authorizer
# https://github.secureserver.net/appservices/cloud-services-lambdas

import datetime
import json
import logging
import os
import sys

from urllib.error import HTTPError, URLError
from ssl import SSLError

from gd_auth.exceptions import InvalidPublicKeyError, TokenExpiredException
from gd_auth.token import AuthToken, BaseAuthToken, TokenBusinessLevel

logger = logging.getLogger("JWT Authorizer")

ALLOW_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "*"}],
}

ANONYMOUS_IDENTITY = "anonymous"
AUTHORIZATION_HEADER = "authorization"
COOKIE_HEADER = "cookie"
DEBUGGING = bool(os.environ.get("DEBUG", "False").capitalize() == "True")
SSO_HOST = os.environ.get("SSO_HOST", "sso.gdcorp.tools")
SSO_BEARER_MARKER = os.environ.get("SSO_BEARER_MARKER", "sso-jwt").lower()
REGION = os.environ.get("AWS_REGION")

if DEBUGGING:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.WARNING)


def handler(event, _):
    """
    SSO Token validator for authenticating API Gateway requests.
    This function will only validate the public sig of the token to insure immutably.
    If cookies are provided in lieu of the sso-jwt header, this will verify *all* SSO cookies are valid.
    """
    headers = event.get("headers", dict()).copy()
    # clear anything not absolutely necessary
    event.clear()

    valid, token = check_request_headers(headers)
    headers.clear()

    if not valid:
        # kick back the 401 instead of 403
        raise Exception("Unauthorized")

    # let it through to the back end Service
    return {"principalId": token, "policyDocument": ALLOW_ALL_POLICY}


def authorize_request_cookies(cookie_header):
    cookie_value = None
    valid = False
    try:
        auth_cookies = []
        for c in cookie_header.split(";"):
            c = c.strip()
            if c.startswith("auth_jomax"):
                auth_cookies.append(c.strip())
        if auth_cookies:
            for cookie in auth_cookies:
                cookie_data = cookie.split("=")
                cookie_value = cookie_data[1]
                valid = validate_token(cookie_value.encode())
                if not valid:
                    raise ValueError(f"Invalid token: {cookie_value}")
    except Exception as err:
        logger.warning(f"Failed to validate auth cookie: {err}")
        valid = False

    if not cookie_value:
        return False, ANONYMOUS_IDENTITY

    return valid, cookie_value


def authorize_request_token(raw_token):
    """
    SSO Token validator for authenticating API Gateway requests.
    This function will only validate the public sig of the token to insure immutably.
    """
    logger.info("Authorizing request...")

    token = None
    valid = False

    # Determine if the bearer token is in the header
    try:
        if (
            raw_token
            and SSO_BEARER_MARKER in raw_token[: len(SSO_BEARER_MARKER)].lower()
        ):
            token = raw_token.split(SSO_BEARER_MARKER)[-1].strip()
            encoded_token = token if isinstance(token, bytes) else token.encode()
            if validate_token(encoded_token):
                valid = True
            else:
                logger.warning(f"Invalid header token encountered {token}")
        else:
            logger.warning("No Auth tokens found in headers")
    except Exception as err:
        logger.debug(f"Token {raw_token} validation failed: {err}")

    return valid, str(token)


def check_request_headers(headers):
    """
    Case insensitively checks the Authorization Header then Cookie Header for SSO JWTs.
    :param headers: Request Header dict
    :return: TokenValidity, Token
    """
    try:
        logger.debug(f"Processing request headers: {json.dumps(headers)}")
        for header_name in headers.keys():
            if header_name.lower() == AUTHORIZATION_HEADER:
                logger.debug(f"Processing authorization header: {headers[header_name]}")
                return authorize_request_token(headers[header_name])
            if header_name.lower() == COOKIE_HEADER:
                logger.debug(f"Processing cookie header: {headers[header_name]}")
                return authorize_request_cookies(headers[header_name])

        logger.warning("No Authorization Headers provided!")
    except Exception as err:
        logger.exception(f"Failed to process headers: {err}")

    # When in doubt, reject
    return False, ANONYMOUS_IDENTITY


def validate_token(raw_token):
    """
    Given the generic nature we need to cheat a bit to get the type info to verify
    """
    try:
        payload = AuthToken.payload(raw_token)
        auth_token = None
        try:
            auth_token = BaseAuthToken(
                raw_token,
                payload,
                SSO_HOST,
                app="JWTAuthorizer",
                forced_heartbeat=False,
            )
        except (HTTPError, URLError, SSLError) as e:
            raise

        # package must be built on Linux per https://github.com/pyca/cryptography/issues/3051
        auth_token._is_valid()

        logger.debug("ftc: %d", auth_token.payload["ftc"])
        logger.debug("factors: %s", json.dumps(auth_token.payload["factors"]))
        logger.debug("accountName: %s", auth_token.payload["accountName"])

        iat = auth_token.payload["iat"]
        iat_str = datetime.datetime.fromtimestamp(
            iat, tz=datetime.timezone.utc
        ).isoformat()
        logger.debug("iat: %d (%s)", iat, iat_str)

        # Medium impact (non delegation) token strength
        # https://confluence.godaddy.com/display/AUTH/Security+Tokens
        auth_token.is_expired(TokenBusinessLevel.MEDIUM)

        return auth_token

    except InvalidPublicKeyError:
        logger.error(f"Invalid Public Key requested. Token: {raw_token}")
        return False
    except TokenExpiredException:
        logger.error(f"Token has expired. Token: {raw_token}")
        return False
    except Exception as err:
        logger.exception(f"Unknown error in validate_token occurred: {err}")
        return False


if __name__ == "__main__":
    """
    Validate a token passed as an argument on the command line.
    """

    # Enable debug level logging for CLI usage
    log_handler = logging.StreamHandler()
    log_handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(log_handler)

    if len(sys.argv) > 1:
        try:
            if validate_token(sys.argv[1]):
                logger.info("Validation passed")
            else:
                logger.info("Validation failed")
        except Exception as err:
            logger.info("Validation failed (exception)")
