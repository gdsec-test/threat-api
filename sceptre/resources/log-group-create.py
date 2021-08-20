#!/usr/bin/env python

import os
import boto3


def create_log_group(log_group_name):
    logs_client = boto3.client("logs")
    try:
        response = logs_client.create_log_group(
            logGroupName=log_group_name,
        )

    except Exception as exception:
        print("group already exists")
    else:
        print(
            "create_log_group() response: %d"
            % response["ResponseMetadata"]["HTTPStatusCode"]
        )

        return response["ResponseMetadata"]["HTTPStatusCode"]


def put_retention_policy(log_group_name, retention_policy):
    logs_client = boto3.client("logs")
    try:
        response = logs_client.put_retention_policy(
            logGroupName=log_group_name, retentionInDays=retention_policy
        )
    except Exception as exception:
        print("exception in retention policy")
    else:
        print(
            "put_retention_policy() response: %d"
            % response["ResponseMetadata"]["HTTPStatusCode"]
        )

        return response["ResponseMetadata"]["HTTPStatusCode"]


def create_log_groups_all_apis():
    for subdir, _, _ in os.walk("../apis/"):
        if (
            (subdir.split("/")[-1] == "apis")
            or ("Library" in subdir)
            or (subdir.split("/")[-1] == "")
        ):
            continue
        log_group_name = "/aws/lambda/" + subdir.split("/")[-1]
        print("------> " + log_group_name)
        response_code = create_log_group(log_group_name)
        if response_code != 200:
            continue
        response_code = put_retention_policy(log_group_name, 30)
        if response_code != 200:
            continue


if __name__ == "__main__":
    create_log_groups_all_apis()
