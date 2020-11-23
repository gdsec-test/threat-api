#!/usr/bin/env python3

"""Test lambda function for ThreatTools API"""

import json
import logging
import sys
import time
import uuid

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)


def asynchronous_wrapper(event, context):
    """Generate a jobId and then re-invoke ourselves asynchronously"""

    log.info("Asynchronous execution requested")
    job = str(uuid.uuid4())

    # Force async off for child call
    event["headers"]["async"] = "false"

    # Supply the generated jobId for the synchronous instance of this job
    event["headers"]["jobId"] = job

    try:
        boto3.client("lambda").invoke(
            FunctionName=context.function_name,
            InvocationType="Event",
            Payload=json.dumps(event),
        )
        return {"statusCode": 202, "body": json.dumps({"jobId": job})}

    except Exception:
        return {"statusCode": 500, "body": json.dumps("Internal Server Error")}


def handler(event, context):
    """Example lambda handler that returns some fields from the event"""

    log.debug("Event: %s", json.dumps(event))

    # Check if the async header was set to request asynchronous execution
    async_hdr = event.get("headers", {}).get("async", "false") == "true"
    if async_hdr:
        return asynchronous_wrapper(event, context)

    log.info("Synchronous execution requested")

    # Build application response
    try:
        path_arg1 = event["pathParameters"]["path_arg1"]
    except Exception:
        path_arg1 = None

    if path_arg1 is not None:
        log.info("Specified path parameter: %s", path_arg1)

    response = {
        "path": event["path"],
        "sourceIp": event["requestContext"]["identity"]["sourceIp"],
        "userAgent": event["requestContext"]["identity"]["userAgent"],
        "message": "Hello from lambda!",
    }

    for attribute in ("pathParameters", "queryStringParameters"):
        if attribute in event and event[attribute]:
            response[attribute] = event[attribute]

    # If we have a jobId, then populate the jobs DynamoDB table
    jobId = event.get("headers", {}).get("jobId")
    if jobId is not None:
        now = int(time.time())
        ttl = now + (86400 * 30)  # 30 days
        job_record = {"jobId": jobId, "ttl": ttl, "endTime": now, "response": response}

        try:
            boto3.resource("dynamodb").Table("jobs").put_item(Item=job_record)
        except Exception:
            log.exception("Unable to update jobs table")

    return {"statusCode": 200, "body": json.dumps(response)}


if __name__ == "__main__":
    # Enable debug level logging for CLI usage

    log_handler = logging.StreamHandler()
    log_handler.setFormatter(
        logging.Formatter("[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t%(message)s")
    )
    log_handler.setLevel(logging.DEBUG)
    log.setLevel(logging.DEBUG)
    log.addHandler(log_handler)

    test_event = {
        "headers": {
            "accept": "*/*",
        },
        "queryStringParameters": None,
        "requestContext": {
            "identity": {
                "sourceIp": "132.148.54.224",
                "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            },
        },
    }

    # Test using a specific method and path argument:
    # ./hello.py [async (false/true)] [path_arg1]

    if len(sys.argv) == 3:
        test_event["headers"]["async"] = sys.argv[1]
        test_event["pathParameters"] = {"path_arg1": sys.argv[2]}
        test_event["path"] = "/hello/%s" % sys.argv[2]

    handler(test_event, None)
