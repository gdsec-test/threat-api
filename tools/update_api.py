#!/usr/bin/env python3

"""\
Programmatically generate and update an API Gateway configuration by walking
the various API lambdas.
"""

import json
import os
import logging
import boto3

APIGATEWAY_ARN_URI_TEMPLATE = "arn:aws:apigateway:us-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-west-2:%s:function:%s/invocations"


def get_apigateway_id():
    """\
    Retrieves the apigateway id
    """
    apigateway_client = boto3.client("apigateway")

    try:
        apigateway_list = [
            x
            for x in apigateway_client.get_rest_apis()["items"]
            if x["name"].startswith("Threat")
        ]
    except Exception as exception:
        logging.exception("apigateway get_rest_api threw an exception")
    else:
        if not apigateway_list:
            # No API Gateways
            return None

        apigateway_id = apigateway_list[0]["id"]
        return apigateway_id


def get_apigateway_template(apigateway_id):
    """\
    Fetches the export from API Gateway for reusing as a template for Swagger.
    Also to update new API Gateway with current state.
    """
    apigateway_client = boto3.client("apigateway")

    try:
        response = apigateway_client.get_export(
            restApiId=get_apigateway_id(),
            stageName="gddeploy",
            exportType="oas30",
            parameters={"extensions": "apigateway"},
        )
    except Exception as exception:
        logging.exception("apigateway get_export exception")
    else:
        template = json.loads(response["body"].read())
        return template


def generate_swagger(json_template):
    """\
    Consolidate swagger specs for individual lambdas and return a consolidated
    swagger spec for the whole API.
    """

    parent_swagger = {}
    for key, value in json_template.items():
        if key == "paths":
            parent_swagger["paths"] = {}
        else:
            parent_swagger[key] = value

    for subdir, _, files in os.walk("../apis/"):
        for filename in files:
            filepath = subdir + os.sep + filename

            if filepath.endswith("swagger.json"):
                with open(filepath, "r") as file:
                    inside_dict = json.load(file)

                for key, value in inside_dict["paths"].items():
                    if key in parent_swagger["paths"].keys():
                        logging.error("%s already exists", key)
                    parent_swagger["paths"][key] = value

    return parent_swagger


def generate_api_definitions(aws_account_id, json_template, apigateway_id):
    """\
    Build an API definition by consolidating information for the various
    lambdas.
    """

    parent_api = json_template.copy()
    apigateway_integration = {
        "type": "aws_proxy",
        "uri": None,  # to be updated later to the invoked lambdas
        "responses": {"default": {"statusCode": "200"}},
        "passthroughBehavior": "when_no_match",
        "httpMethod": "POST",
        "contentHandling": "CONVERT_TO_TEXT",
    }
    security_key = apigateway_id + "-JWTAuthorizer"
    api_gateway_security_tag = {security_key: []}

    # get the template copied retaining the swagger paths
    for key, value in json_template.items():
        if key == "paths":
            parent_api["paths"] = {}
            for paths, path_values in json_template["paths"].items():
                if paths.startswith("/swagger"):
                    parent_api["paths"][paths] = path_values
        else:
            parent_api[key] = value

    # loop through the current dictionaries, add to the paths with apigateway definitions
    for subdir, _, files in os.walk("../apis/"):
        for filename in files:
            filepath = subdir + os.sep + filename

            if filepath.endswith("swagger.json"):
                with open(filepath, "r") as file:
                    inside_dict = json.load(file)

                for key, value in inside_dict["paths"].items():
                    # for duplicate paths - throw error
                    if key in parent_api["paths"].keys():
                        logging.error("%s already exists", key)
                    # loop through and add an api-gateway connection to all path-methods
                    else:
                        parent_api["paths"][key] = value

                        # taking the value after first os.sep - points the directory
                        lambda_name = key.split(os.sep)[1]
                        uri = APIGATEWAY_ARN_URI_TEMPLATE % (
                            aws_account_id,
                            lambda_name,
                        )
                        temp = apigateway_integration.copy()
                        temp["uri"] = uri

                        # For every method of the path, loop through and add the apigateway, security data
                        for methods in parent_api["paths"][key]:
                            parent_api["paths"][key][methods][
                                "x-amazon-apigateway-integration"
                            ] = temp
                            parent_api["paths"][key][methods]["security"] = [
                                api_gateway_security_tag
                            ]

    return parent_api


def upload_swagger_json(swagger_spec):
    """\
    Copy the generated swagger spec to S3 where it's reference by Swagger UI.
    """

    s3 = boto3.resource("s3")
    try:
        bucket_list = [
            x for x in s3.buckets.all() if x.name.endswith("swagger-ui-bucket")
        ]
    except Exception as exception:
        logging.exception("couldn't retrieve s3 buckets")
    else:
        if bucket_list:
            try:
                bucket_list[0].put_object(
                    Body=json.dumps(swagger_spec), Key="swagger.json"
                )
            except Exception as exception:
                logging.exception("exception in putting swagger.json object in s3")


def update_apigateway(api_spec):
    """\
    Update the API Gateway with the provided specification, and deploy it.
    """

    apigateway_client = boto3.client("apigateway")

    try:
        apigateway_list = [
            x
            for x in apigateway_client.get_rest_apis()["items"]
            if x["name"].startswith("Threat")
        ]
    except Exception as exception:
        logging.exception("apigateway get_rest_apis threw an exception")
    else:
        if not apigateway_list:
            # No API Gateways
            return

        apigateway_id = apigateway_list[0]["id"]

    try:
        response = apigateway_client.put_rest_api(
            restApiId=apigateway_id,
            mode="overwrite",
            failOnWarnings=True,
            body=json.dumps(api_spec),
        )
    except Exception as exception:
        logging.exception("exception in put_rest_api in writing to apigateway")
    else:
        print(
            "put_rest_api() response: %d"
            % response["ResponseMetadata"]["HTTPStatusCode"]
        )

    try:
        response = apigateway_client.create_deployment(
            restApiId=apigateway_id, stageName="gddeploy"
        )
    except Exception as exception:
        logging.exception("exception in apigateway create_deployment")
    else:
        print(
            "create_deployment() response: %d"
            % response["ResponseMetadata"]["HTTPStatusCode"]
        )


if __name__ == "__main__":
    # Update swagger.json for SwaggerUI
    apigateway_id = get_apigateway_id()
    apigateway_json_template = get_apigateway_template(apigateway_id)

    if apigateway_json_template is not None:
        swagger_json = generate_swagger(apigateway_json_template)
        upload_swagger_json(swagger_json)

        # Update the API Gateway specification
        sts = boto3.client("sts")
        try:
            aws_account_id = sts.get_caller_identity()["Account"]
        except Exception as exception:
            logging.exception("get_caller_identity couldn't be retrieved")
        else:
            api_definitions = generate_api_definitions(
                aws_account_id,
                apigateway_json_template,
                apigateway_id,
            )

            update_apigateway(api_definitions)
    else:
        logging.error("json_template couldn't be retrieved")
