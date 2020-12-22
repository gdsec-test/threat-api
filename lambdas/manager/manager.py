#!/usr/bin/env python3

"""Sample manager lambda function for ThreatTools API"""

import decimal
import json
import logging
import sys
import time
import uuid

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

try:
    JOB_REQUESTS_TOPIC = boto3.client("ssm").get_parameter(
        Name="/ThreatTools/JobRequests"
    )["Parameter"]["Value"]
except Exception:
    JOB_REQUESTS_TOPIC = "UNKNOWN"


class DecimalEncoder(json.JSONEncoder):
    """Helper class to convert a DynamoDB item to JSON"""

    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            return int(o)
        return super().default(o)


def lookup_job(job_id):
    """Job lookup"""

    try:
        results = (
            boto3.resource("dynamodb").Table("jobs").get_item(Key={"job_id": job_id})
        )
        if "Item" in results:
            return 200, results["Item"]

        return 404, "Not Found"

    except Exception:
        return 500, "Internal Server Error"


def create_job(body):
    """Create new job"""

    # Generate a unique job_id
    job_id = str(uuid.uuid4())

    now = int(time.time())

    # Generate a new job record
    job_record = {
        "job_id": job_id,
        "ttl": now + (86400 * 30),
        "startTime": now,
        "request": body,
        "response": {},
    }

    try:
        boto3.resource("dynamodb").Table("jobs").put_item(Item=job_record)
    except Exception:
        log.exception("Unable to update jobs table")
        return 500, "Internal Server Error"

    try:
        boto3.resource("sns").Topic(JOB_REQUESTS_TOPIC).publish(
            Message=json.dumps(job_record)
        )
    except Exception:
        log.exception("Unable to publish job to SNS topic")
        return 500, "Internal Server Error"

    return 202, {"job_id": job_id}


def list_jobs():
    """List job_ids"""

    try:
        results = boto3.resource("dynamodb").Table("jobs").scan()
        if "Items" in results:
            # Sort by ttl (most recent first)
            jobs = sorted(
                results["Items"], key=lambda k: k.get("ttl", 9999999999), reverse=True
            )
            return 200, [x["job_id"] for x in jobs]

        return 200, []

    except Exception:
        return 500, "Internal Server Error"


# pylint: disable=unused-argument
def handler(event, context):
    """Route the request to the right function for processing"""

    log.info("Event: %s", json.dumps(event))

    response_code = 200
    response_body = {}
    try:
        resource = event["resource"]

        if resource == "/job/{job_id}":
            job_id = event["pathParameters"]["job_id"]
            response_code, response_body = lookup_job(job_id)
        elif resource == "/job":
            body = json.loads(event["body"])
            response_code, response_body = create_job(body)
        elif resource == "/jobs":
            response_code, response_body = list_jobs()
        else:
            log.error("No matching request pattern")
            response_code, response_body = 400, "Bad Request"

    except Exception:
        log.exception("Unable to parse event body:")
        response_code, response_body = 400, "Bad Request"

    return {
        "statusCode": response_code,
        "body": json.dumps(response_body, cls=DecimalEncoder),
    }


if __name__ == "__main__":
    # Enable debug level logging for CLI usage

    log_handler = logging.StreamHandler()
    log_handler.setFormatter(
        logging.Formatter("[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t%(message)s")
    )
    log_handler.setLevel(logging.DEBUG)
    log.setLevel(logging.DEBUG)
    log.addHandler(log_handler)

    if len(sys.argv) == 2:
        test_event = json.loads(open(sys.argv[1]))
        handler(test_event, None)
