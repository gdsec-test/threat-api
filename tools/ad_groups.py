#!/usr/bin/env python3

"""Simple script to get AD groups for a JWT"""

import sys
import requests


def get_ad_groups(jwt):
    """Get a list of AD groups from a JWT"""
    try:
        response = requests.get(
            "https://sso.gdcorp.tools/api/my/ad_membership",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "sso-jwt " + jwt,
            },
            timeout=5.0,
        )
        groups = response.json()["data"]["groups"]

    except ValueError:
        # In case of error, Return empty list
        print(response.reason, file=sys.stderr)
        groups = []

    except KeyError:
        # In case of error, Return empty list
        print(response.reason, file=sys.stderr)
        groups = []

    return groups


if __name__ == "__main__":
    if len(sys.argv) == 2:
        supplied_jwt = sys.argv[1]
        ad_groups = get_ad_groups(supplied_jwt)

        for ad_group in sorted(ad_groups):
            print(ad_group)

    else:
        print("Please provide JWT as an argument", file=sys.stderr)
        sys.exit(1)
