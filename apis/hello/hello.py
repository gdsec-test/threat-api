"""Test lambda function for ThreatTools API"""

import json

# pylint: disable=unused-argument
def handler(event, context):
    """Example lambda handler that returns some fields from the event"""

    response = {
        "path": event["requestContext"]["path"],
        "sourceIp": event["requestContext"]["identity"]["sourceIp"],
        "userAgent": event["requestContext"]["identity"]["userAgent"],
        "message": "Hello from lambda!",
    }

    for attribute in ("pathParameters", "queryStringParameters"):
        if attribute in event and event[attribute]:
            response[attribute] = event[attribute]

    return {"statusCode": 200, "body": json.dumps(response)}
