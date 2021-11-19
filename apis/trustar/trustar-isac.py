#!/usr/bin/env python3

import csv
import datetime
import io
import json
import logging
import sys
from typing import Any, Dict, Generator, List

import boto3
import trustar
from enums import EventKind, EventCategory, EventType, EventOutcome
from event import Event
from logger import AppSecFormatter, AppSecLogger
from botocore.exceptions import ClientError
from elasticapm import Client
#from elasticapm.contrib.starlette import make_apm_client, ElasticAPM

AWS_REGION = "us-west-2"
MODULE_NAME = "trustar"
SECRETS_MANAGER_ID = "/ThreatTools/Integrations/trustar"
APM_SERVER_URL = "/ThreatTools/Integrations/ELASTIC_APM_SERVER_URL"  # nosec
APM_TOKEN = "/ThreatTools/Integrations/ELASTIC_APM_SECRET_TOKEN"  # nosec


def initAppSecHandler() -> logging.StreamHandler:
    """Initialize the custom AppSecLogging Handler object"""
    handler = logging.StreamHandler()
    cloud_account_id = boto3.client("sts").get_caller_identity()["Account"]
    cloud_instance_id = "arn:aws:lambda:{}:{}:function:{}".format(
        AWS_REGION, MODULE_NAME, cloud_account_id
    )
    formatter = AppSecFormatter(
        "threat-api", "prod", ["threat-intel"], cloud_account_id, cloud_instance_id
    )
    handler.setFormatter(formatter)
    return handler


logging.setLoggerClass(AppSecLogger)
log = logging.getLogger("app")
log.setLevel(logging.INFO)
log.addHandler(initAppSecHandler())


def retrieveSecrets() -> Dict[str, str]:
    """Retrieve the API information from Secrets Manager"""
    sm_client = boto3.client("secretsmanager")

    secret = None
    try:
        secret = sm_client.get_secret_value(SecretId=SECRETS_MANAGER_ID)
    except Exception as e:
        log.error("Exception while getting the secret values")
        log.error(e)
        return None

    if secret is None:
        log.error(
            "Failed to get the {} secrets but did not throw an exception".format(
                SECRETS_MANAGER_ID
            )
        )
        return None
    
    return json.loads(secret["SecretString"])


def configureTrustar() -> trustar.TruStar:
    """Configure and initialize the TruSTAR API client object"""
    secrets = retrieveSecrets()
    if secrets is None:
        return None

    config = {
        "auth_endpoint": "https://api.trustar.co/oauth/token",
        "api_endpoint": "https://api.trustar.co/api/1.3",
        "user_api_key": secrets["user_api_key"],
        "user_api_secret": secrets["user_api_secret"],
        "client_metatag": secrets["client_metatag"],
    }
    return trustar.TruStar(config=config)


def lookupIp(ts: trustar.TruStar, ip: str) -> Dict[str, Any]:
    return ts.search_indicators(search_term=ip, indicator_types=["IP"])


def lookupMd5(ts: trustar.TruStar, hash: str) -> Dict[str, Any]:
    return ts.search_indicators(search_term=hash, indicator_types=["MD5"])


def lookupSha1(ts: trustar.TruStar, hash: str) -> Dict[str, Any]:
    return ts.search_indicators(search_term=hash, indicator_types=["SHA1"])


def lookupSha256(ts: trustar.TruStar, hash: str) -> Dict[str, Any]:
    return ts.search_indicators(search_term=hash, indicator_types=["SHA256"])


def lookupDomainOrUrl(ts: trustar.TruStar, both: str) -> Dict[str, Any]:
    return ts.search_indicators(search_term=both, indicator_types=["URL"])


def lookupCve(ts: trustar.TruStar, cve: str) -> Dict[str, Any]:
    return ts.search_indicators(search_term=cve, indicator_types=["CVE"])


def lookupEmailAddress(ts: trustar.TruStar, address: str) -> Dict[str, Any]:
    return ts.search_indicators(search_term=address, indicator_types=["EMAIL_ADDRESS"])


def convertIndicator(
    ioc: str, indicators: Generator[trustar.Indicator, None, None]
) -> List[Dict[str, Any]]:
    """Convert a generator of Indicator objects into a list of dictionaries"""
    if indicators is not None:
        return [indicator.to_dict() for indicator in indicators]
    log.warn("Failed to look up the artifact: " + ioc)
    return list()


def convertTimestamp(epoch: int) -> str:
    """Convert a timestamp given in epoch milliseconds into a UTC string representation"""
    return datetime.datetime.utcfromtimestamp(epoch / 1000).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def convertToCsv(ioc_dict: Dict[str, List[Dict[str, Any]]]) -> str:
    """Convert the IoC dictionary to a CSV representation"""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["ioc", "firstSeen", "lastSeen"])
    for ioc, indicators in ioc_dict.items():
        for indicator in indicators:
            writer.writerow(
                [
                    ioc,
                    convertTimestamp(indicator["firstSeen"]),
                    convertTimestamp(indicator["lastSeen"]),
                ]
            )
    return output.getvalue()


def process(job_request: Dict[str, str]) -> Dict[str, str]:
    """Process an individual record"""
    try:
        job_id = job_request["jobId"]
        job_request_body = json.loads(job_request["submission"]["body"])
        print(job_request_body)
    except Exception as e:
        log.error("Exception while loading the request body")
        log.error(e)
        job_id = "UNKNOWN"
        job_request_body = {}

    modules_requested = job_request_body.get("modules", list())
    if MODULE_NAME not in modules_requested:
        return {}

    ts = configureTrustar()
    if ts is None:
        log.error("Failed to instantiate the TruSTAR object")
        job_id = "UNKNOWN"
        job_request_body = {}

    ioc_type = job_request_body.get("iocType", "")
    ioc_list = job_request_body.get("iocs", list())

    ioc_dict = dict()
    if ioc_type == "DOMAIN":
        log.info("Processing {} domain artifact(s)".format(len(ioc_list)))
        ioc_dict = {
            ioc: convertIndicator(ioc, lookupDomainOrUrl(ts, ioc)) for ioc in ioc_list
        }
    elif ioc_type == "MD5":
        log.info("Processing {} MD5 hash artifact(s)".format(len(ioc_list)))
        ioc_dict = {ioc: convertIndicator(ioc, lookupMd5(ts, ioc)) for ioc in ioc_list}
    elif ioc_type == "SHA1":
        log.info("Processing {} SHA1 hash artifact(s)".format(len(ioc_list)))
        ioc_dict = {ioc: convertIndicator(ioc, lookupSha1(ts, ioc)) for ioc in ioc_list}
    elif ioc_type == "SHA256":
        log.info("Processing {} SHA256 hash artifact(s)".format(len(ioc_list)))
        ioc_dict = {
            ioc: convertIndicator(ioc, lookupSha256(ts, ioc)) for ioc in ioc_list
        }
    elif ioc_type == "IP":
        log.info("Processing {} IP address artifact(s)".format(len(ioc_list)))
        ioc_dict = {ioc: convertIndicator(ioc, lookupIp(ts, ioc)) for ioc in ioc_list}
    elif ioc_type == "URL":
        log.info("Processing {} URL artifact(s)".format(len(ioc_list)))
        ioc_dict = {
            ioc: convertIndicator(ioc, lookupDomainOrUrl(ts, ioc)) for ioc in ioc_list
        }
    elif ioc_type == "EMAIL":
        log.info("Processing {} EMAIL address artifact(s)".format(len(ioc_list)))
        ioc_dict = {
            ioc: convertIndicator(ioc, lookupEmailAddress(ts, ioc)) for ioc in ioc_list
        }
    elif ioc_type == "CVE":
        log.info("Processing {} CVE artifact(s)".format(len(ioc_list)))
        ioc_dict = {ioc: convertIndicator(ioc, lookupCve(ts, ioc)) for ioc in ioc_list}
    else:
        log.warn("{} is an unsupported artifact type".format(ioc_type))

    response_count = sum(map(len, ioc_dict.values()))
    metadata = (
        "1 response found"
        if response_count == 1
        else "{} responses found".format(response_count),
    )
    response_message = {
        "module_name": MODULE_NAME,
        "jobId": job_id,
        "response": json.dumps(
            [
                {
                    "Title": "TruSTAR/ISAC Query",
                    "Metadata": metadata,
                    "DataType": "csv",
                    "Data": convertToCsv(ioc_dict),
                }
            ]
        ),
    }

    log.info("Response: " + str(response_message))
    return response_message

def get_secret(name, region_name):  # nosec
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)
    try:
        get_secret_value_response = client.get_secret_value(SecretId=name)
    except ClientError as e:
            print("An error occurred on service side")
    else:
        return get_secret_value_response

# pylint: disable=unused-argument
def handler(event: Dict[str, Any], context) -> List[Dict[str, str]]:
    """Route the request to the right function for processing"""

    # event has JWT; don't log
    # log.info("Event: %s", json.dumps(event))

    # The input event from SNS contains a list of records, so call process()
    # for each one and return a list of the results.
    try:
        return [
            process(json.loads(record["Sns"]["Message"])) for record in event["Records"]
        ]
    except Exception:
        log.exception("Unable to parse event body")


if __name__ == "__main__":
    # Enable debug level logging for CLI usage
    apm_secret_token = get_secret(APM_TOKEN, AWS_REGION)["SecretString"]  # nosec
    apm_server_url = get_secret(APM_SERVER_URL, AWS_REGION)["SecretString"]  # nosec
    client = Client(service_name=MODULE_NAME, server_url=apm_server_url, secret_token=apm_secret_token)
    client.begin_transaction("trustar..lookup")

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
    
    client.end_transaction("trustar..lookup")
