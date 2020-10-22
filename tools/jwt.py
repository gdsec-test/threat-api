#!/usr/bin/env python3

"""Simple script to get a JWT for a JOMAX employee"""

import getpass
import json
import requests


def get_jwt(username, password):
    """Get a JWT from SSO (JOMAX realm)"""
    try:
        response = requests.post(
            "https://sso.godaddy.com/v1/api/token",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            data=json.dumps(
                {"username": username, "password": password, "realm": "jomax"}
            ),
            timeout=5.0,
        )
        jwt = response.json()["data"]

    except ValueError:
        # Not valid JSON
        jwt = response.reason

    except KeyError:
        # Invalid auth; dump the response
        jwt = response.json()

    return jwt


if __name__ == "__main__":
    supplied_username = input("Enter JOMAX username: ")
    supplied_password = getpass.getpass("Enter JOMAX password: ")

    print(get_jwt(supplied_username, supplied_password))
