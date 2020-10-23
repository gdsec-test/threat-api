#!/usr/bin/env python3

"""\
Programmatically generate and update an API Gateway configuration by walking
the various API lambdas.
"""

import boto3

# NOTE: this uses hard-coded files for now; eventually this will be dynamically
# generated and wired into CICD


def generate_swagger():
    """\
    Consolidate swagger specs for individual lambdas and return a consolidated
    swagger spec for the whole API.  For now, just return a hardcoded file
    present in the source tree.
    """

    return open("../swagger.json").read()


def upload_swagger_json(swagger_spec):
    """\
    Copy the generated swagger spec to S3 where it's reference by Swagger UI.
    """

    s3 = boto3.resource("s3")
    bucket_list = [x for x in s3.buckets.all() if x.name.endswith("swagger-ui-bucket")]

    if bucket_list:
        bucket_list[0].put_object(Body=swagger_spec, Key="swagger.json")


def generate_api_definitions():
    """\
    Build an API definition by consolidating information for the various
    lambdas.  For now, just return a hardcoded file present in the source tree,
    but replace symbolic references to the AWS account number with the real
    account number.
    """

    sts = boto3.client("sts")
    aws_account_id = sts.get_caller_identity()["Account"]

    return open("../api.json").read().replace("___AWS_ACCOUNT___", aws_account_id)


def update_apigateway(api_spec):
    """\
    Update the API Gateway with the provided specification, and deploy it.
    """

    apigateway_client = boto3.client("apigateway")

    apigateway_list = [
        x
        for x in apigateway_client.get_rest_apis()["items"]
        if x["name"].startswith("Threat")
    ]
    if not apigateway_list:
        # No API Gateways
        return

    apigateway_id = apigateway_list[0]["id"]

    response = apigateway_client.put_rest_api(
        restApiId=apigateway_id, mode="merge", body=api_spec
    )

    print(
        "put_rest_api() response: %d" % response["ResponseMetadata"]["HTTPStatusCode"]
    )

    response = apigateway_client.create_deployment(
        restApiId=apigateway_id, stageName="gddeploy"
    )

    print(
        "create_deployment() response: %d"
        % response["ResponseMetadata"]["HTTPStatusCode"]
    )


if __name__ == "__main__":
    # Update swagger.json for SwaggerUI
    swagger_json = generate_swagger()
    upload_swagger_json(swagger_json)

    # Update the API Gateway specification
    api_definitions = generate_api_definitions()
    update_apigateway(api_definitions)
