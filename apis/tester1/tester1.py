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


def process(job_request):
    """Process an individual record"""

    # job_request has JWT; don't log
    # log.info("Job (request): %s", json.dumps(job_request))

    try:
        job_id = job_request["jobID"]
        job_request_body = json.loads(job_request["original_request"]["body"])
    except Exception:
        job_id = "UNKNOWN"
        job_request_body = {}

    log.info("Job (request body): %s", json.dumps(job_request_body))

    job_response = {}

    job_response["job_id"] = job_id
    job_response["module_name"] = "tester1"
    job_response["response"] = json.dumps(
        {
            "ts": str(time.time()),
            "output": "Hello from tester1!",
            "job_request_body": job_request_body,
        }
    )

    log.info("Job (response): %s", json.dumps(job_response))

    try:
        boto3.client("sqs").send_message(
            QueueUrl=JOB_RESPONSES_QUEUE, MessageBody=json.dumps(job_response)
        )
    except Exception:
        log.exception("SQS exception:")


# pylint: disable=unused-argument
def handler(event, context):
    """Route the request to the right function for processing"""

    # event has JWT; don't log
    # log.info("Event: %s", json.dumps(event))

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
