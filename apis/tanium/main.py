#!/usr/bin/env python3

import json
import sys
from typing import Any, Dict, Generator, List, Set, Tuple
import logging
import boto3
import botocore
from requests.exceptions import HTTPError
from logger import AppSecFormatter, AppSecLogger

AWS_REGION = "us-west-2"
MODULE_NAME = "tanium"
CLUSTER = "api-ecstask-cluster"
TASK_DEFINITION_FAMILY = "api-ecstask-task"
SUBNETS = "/AdminParams/VPC/PrivateSubnets"
SECURITY_GROUPS = "/AdminParams/VPC/PrivateSG"


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


def getSubnets() -> str:
    ssm = boto3.client("ssm")
    subnets = ssm.get_parameter(Name=SUBNETS, WithDecryption=True)
    subnets = subnets["Parameter"]["Value"].split(",")
    if len(subnets) < 1:
        log.error("No subnets found for execution: {}".format(subnets))
    return subnets


def getSecurityGroups() -> str:
    ssm = boto3.client("ssm")
    securityGroups = ssm.get_parameter(Name=SECURITY_GROUPS, WithDecryption=True)
    securityGroups = securityGroups["Parameter"]["Value"].split(",")
    if len(securityGroups) < 1:
        log.error("No security Groups found for execution: {}".format(securityGroups))
    return securityGroups


def process(job_request: Dict[str, str]) -> Dict[str, str]:
    ecs = boto3.client("ecs")

    try:
        job_id = job_request["jobId"]
        job_request_body = json.loads(job_request["submission"]["body"])
        ioc_type = job_request_body.get("iocType", "")
        ioc_list = job_request_body.get("iocs", list())
        modules_requested = job_request_body.get("modules", list())
    except Exception as e:
        log.error("Exception while loading the request body: {}".format(e))
        job_id = "UNKNOWN"
        job_request_body = {}

    if MODULE_NAME not in modules_requested:
        log.info(
            "Modules {} are not supported, returning empty result".format(
                modules_requested
            )
        )
        return {}

    if ioc_type == "CPE" or ioc_type == "GODADDY_HOSTNAME":
        subnets = getSubnets()
        securityGroups = getSecurityGroups()
        log.info("Starting task")
        task_execution = {
            "cluster": CLUSTER,
            "taskDefinition": TASK_DEFINITION_FAMILY,
            "count": 1,
            "launchType": "FARGATE",
            "platformVersion": "LATEST",
            "networkConfiguration": {
                "awsvpcConfiguration": {
                    "securityGroups": securityGroups,
                    "subnets": subnets,
                    "assignPublicIp": "ENABLED",
                }
            },
            "overrides": {
                "containerOverrides": [
                    {
                        "name": TASK_DEFINITION_FAMILY,
                        "environment": [
                            {"name": "IOC_TYPE", "value": ioc_type},
                            {"name": "IOC_LIST", "value": ",".join(map(str, ioc_list))},
                            {"name": "JOB_ID", "value": job_id},
                            {
                                "name": "MODULE_NAME",
                                "value": ",".join(map(str, modules_requested)),
                            },
                        ],
                    }
                ]
            },
        }
        log.info("Starting  task with execution: {}".format(task_execution))
        try:
            response = ecs.run_task(**task_execution)
            log.info(
                "Task is running. Response successfully received: {}".format(response)
            )

        except BaseException as err:
            log.error("Run task failed: {0}".format(err))
            return None
    else:
        log.error("{} is an unsupported artifact type".format(ioc_type))

    response_message = {"module_name": MODULE_NAME, "jobId": job_id}

    log.info("Finished running task: " + str(response_message))
    return response_message


def handler(event: Dict[str, Any], context) -> List[Dict[str, str]]:
    log.addHandler(initAppSecHandler())
    try:
        return [
            process(json.loads(record["Sns"]["Message"])) for record in event["Records"]
        ]
    except Exception as e:
        log.error("Failed to process task: {0}. Exception: {1}".format(event, e))


if __name__ == "__main__":
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(
        logging.Formatter("[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t%(message)s")
    )
    log_handler.setLevel(logging.DEBUG)
    log.setLevel(logging.DEBUG)
    log.addHandler(log_handler)
    test_event = {
        "Records": [
            {
                "Sns": {
                    "Message": """{
                        "jobId": "TESTJOB",
                        "submission": { "body": { "modules": ["tanium"], "iocType": "CPE", "iocs": [ "cpe1", "cpe2" ] } }
                    }"""
                }
            }
        ]
    }
    # test_event = json.loads(open(sys.argv[1]))
    handler(test_event, None)
