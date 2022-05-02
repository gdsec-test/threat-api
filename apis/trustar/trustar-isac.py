#!/usr/bin/env python3

from collections import defaultdict
import csv
import datetime
import io
import json
import logging
import sys
from urllib.error import HTTPError
from typing import Any, Dict, Generator, List, Set, Tuple

import boto3
import trustar
from enums import EventKind, EventCategory, EventType, EventOutcome
from event import Event
from logger import AppSecFormatter, AppSecLogger
from requests.exceptions import HTTPError

AWS_REGION = "us-west-2"
MODULE_NAME = "trustar"
SECRETS_MANAGER_ID = "/ThreatTools/Integrations/trustar"


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


def retrieveCorrelatedIndicators(ts: trustar.TruStar, ioc: str) -> Tuple[Dict[str, Set[str]], str]:
    """Retrieve a Report object associated with the IoC provided
    
    :param ts: TruSTAR object for issuing API queries
    :param ioc: one IoC to find correlated IoCs
    :returns: dictionary of correlated IoCs where the keys are the IoC types, and an error message
    """

    # get all the reports correlated to the provided IoC
    reports = ts.get_correlated_reports([ioc])
    if reports is None:
        err_msg = f"Null returned when retrieving reports correlated with {ioc}"
        log.error(err_msg)
        return dict(), err_msg

    # pivot: retrieve all IoCs correlated with those reports
    unique_iocs = defaultdict(set)
    for report in reports:
        for corr_ioc in ts.get_indicators_for_report(report.id):
            unique_iocs[corr_ioc.type].add(corr_ioc.value)

    return unique_iocs, None


def convertIndicator(
    ioc: str, indicators: Generator[trustar.Indicator, None, None]
) -> List[Dict[str, Any]]:
    """Convert a generator of Indicator objects into a list of dictionaries"""
    if indicators is not None:
        try:
            return [indicator.to_dict() for indicator in indicators]
        except HTTPError as e:
            # HTTP 429 - rate limiting - may apply here
            log.error(e)
            return list()
    log.warn("Failed to look up the artifact: " + ioc)
    return list()


def convertTimestamp(epoch: int) -> str:
    """Convert a timestamp given in epoch milliseconds into a UTC string representation
    
    :param epoch: Linux epoch time in integer format
    :returns: time in string form ISO formatted
    """
    return datetime.datetime.utcfromtimestamp(epoch / 1000).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def dumpSet(obj:Set[Any]) -> List[Any]:
    """Method for casting a set into a list for JSON serialzation"""
    return list(obj)


def convertToCsv(ioc_dict: Dict[str, List[Dict[str, Any]]], ioc_correlations: Dict[str, str]) -> str:
    """Convert the IoC dictionary to a CSV representation
    
    :params ioc_dict: 
    :params ioc_correlations: 
    :returns: CSV string
    """
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["ioc", "firstSeen", "lastSeen", "sightings", "correlations"])
    for ioc, indicators in ioc_dict.items():
        for indicator in indicators:
            writer.writerow(
                [
                    ioc,
                    convertTimestamp(indicator["firstSeen"]),
                    convertTimestamp(indicator["lastSeen"]),
                    "0" if indicator["sightings"] is None else str(indicator["sightings"]),
                    json.dumps(ioc_correlations.get(ioc, dict()), default=dumpSet)
                ]
            )
    return output.getvalue()


def process(job_request: Dict[str, str]) -> Dict[str, str]:
    """Process an individual record"""
    err_msg = None

    try:
        job_id = job_request["jobId"]
        job_request_body = json.loads(job_request["submission"]["body"])
    except Exception as e:
        err_msg = "Exception while loading the request body: " + str(e)
        log.error(err_msg)
        job_id = "UNKNOWN"
        job_request_body = {}

    modules_requested = job_request_body.get("modules", list())
    if MODULE_NAME not in modules_requested:
        return {}

    ts = configureTrustar()
    if ts is None:
        err_msg = "Failed to instantiate the TruSTAR object"
        log.error(err_msg)
        job_id = "UNKNOWN"
        job_request_body = {}

    ioc_type = job_request_body.get("iocType", "")
    ioc_list = job_request_body.get("iocs", list())

    # get data for the IoCs themselves
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

    # search for correlated IoCs
    ioc_correlations = dict()
    for ioc in ioc_dict:
        ioc_corr, err_msg = retrieveCorrelatedIndicators(ts, ioc)
        if err_msg is not None: break
        ioc_correlations[ioc] = ioc_corr

    response_count = sum(map(len, ioc_dict.values()))
    metadata = [ f"{response_count} response(s) found" ]
    if err_msg is not None:
        metadata.append(err_msg)
    response_message = {
        "module_name": MODULE_NAME,
        "jobId": job_id,
        "response": json.dumps(
            [
                {
                    "Title": "TruSTAR/ISAC Query",
                    "Metadata": metadata,
                    "DataType": "csv",
                    "Data": convertToCsv(ioc_dict, ioc_correlations),
                }
            ]
        ),
    }

    log.info("Response: " + str(response_message))
    return response_message


# pylint: disable=unused-argument
def handler(event: Dict[str, Any], context) -> List[Dict[str, str]]:
    """Route the request to the right function for processing"""

    # event has JWT; don't log
    # log.info("Event: %s", json.dumps(event))

    # The input event from SNS contains a list of records, so call process()
    # for each one and return a list of the results.
    
    log.addHandler(initAppSecHandler())

    try:
        return [
            process(json.loads(record["Sns"]["Message"])) for record in event["Records"]
        ]
    except Exception:
        log.exception("Unable to parse event body")


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
