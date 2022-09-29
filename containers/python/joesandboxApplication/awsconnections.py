import json
import logging
from typing import Dict

import boto3
from botocore.exceptions import ClientError

AWS_REGION = "us-west-2"
SECRETS_MANAGER_ID = "/ThreatTools/Integrations/joesandbox"
PARAMETER_STORE_S3_BUCKET_NAME = "/Quicksand/forensic-storage-bucket"


def retrieve_aws_parameter_store() -> str:
    ssm_client = boto3.client("ssm", region_name=AWS_REGION)
    response = ssm_client.get_parameter(
        Name=PARAMETER_STORE_S3_BUCKET_NAME, WithDecryption=False
    )

    return response["Parameter"]["Value"]


def retrieve_secrets() -> Dict[str, str]:
    """Retrieve the API information from Secrets Manager"""
    sm_client = boto3.client("secretsmanager", region_name=AWS_REGION)

    secret = None
    try:
        secret = sm_client.get_secret_value(SecretId=SECRETS_MANAGER_ID)
    except Exception as e:
        logging.log.error("Exception while getting the secret values")
        logging.log.error(e)
        return None

    if secret is None:
        logging.log.error(
            "Failed to get the {} secrets but did not throw an exception".format(
                SECRETS_MANAGER_ID
            )
        )
        return None

    return json.loads(secret["SecretString"])


def upload_file_to_s3(file_name, object_name) -> bool:
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # Upload the file
    s3_client = boto3.client("s3", region_name=AWS_REGION)
    bucket_name = retrieve_aws_parameter_store()
    try:
        response = s3_client.upload_file(
            file_name,
            bucket_name,
            object_name,
            ExtraArgs={"ACL": "bucket-owner-full-control"},
        )
    except ClientError as e:
        logging.error(e)
        return False
    return True
