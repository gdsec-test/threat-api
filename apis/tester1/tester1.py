#!/usr/bin/env python3

"""Sample lambda function for ThreatTools API"""

import json
import logging
import sys
import time

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

try:
    JOB_RESPONSES_QUEUE = boto3.client("ssm").get_parameter(
        Name="/ThreatTools/JobResponses"
    )["Parameter"]["Value"]
except Exception:
    JOB_RESPONSES_QUEUE = "UNKNOWN"


def process(job):
    """Process an individual record"""

    log.info("Job (request): %s", json.dumps(job))

    job["response"] = {}
    job["response"]["tester1"] = {
        "ts": str(time.time()),
        "output": "Hello from tester1!",
    }

    log.info("Job (response): %s", json.dumps(job))

    try:
        boto3.client("sqs").send_message(
            QueueUrl=JOB_RESPONSES_QUEUE, MessageBody=json.dumps(job)
        )
    except Exception:
        log.exception("SQS exception:")


# pylint: disable=unused-argument
def handler(event, context):
    """Route the request to the right function for processing"""

    log.info("Event: %s", json.dumps(event))

    try:
        for record in event["Records"]:
            process(json.loads(record["Sns"]["Message"]))
    except Exception:
        log.exception("Unable to parse event body:")


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
