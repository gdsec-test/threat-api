#!/usr/bin/env python3

"""\
Programmatically generate and update an API Gateway configuration by walking
the various API lambdas.
"""

import boto3
import json 
import os
import logging

# NOTE: this uses hard-coded files for now; eventually this will be dynamically
# generated and wired into CICD


def generate_swagger():
    """\
    Consolidate swagger specs for individual lambdas and return a consolidated
    swagger spec for the whole API.  For now, just return a hardcoded file
    present in the source tree.
    """

    parent_swagger = json.load(open("../swagger.json"))

    for subdir, dirs, files in os.walk("../apis/"):
        for filename in files:
            filepath = subdir + os.sep + filename

            if filepath.endswith("swagger.json"):
                inside_dict = json.load(open(filepath))

                for key,value in inside_dict["paths"].items():
                    if key in parent_swagger["paths"].keys():
                        logging.error(key+' already exists')
                    parent_swagger["paths"][key]=value

    with open("../swagger.json", "w") as fp:
        json.dump(parent_swagger, fp, indent=2)
    
    return {'bytes': open("../swagger.json").read(), 'dictionary':parent_swagger}

    # # reurn the dictionary ?
    # return json.dumps(parent_swagger)



def upload_swagger_json(swagger_spec):
    """\
    Copy the generated swagger spec to S3 where it's reference by Swagger UI.
    """

    s3 = boto3.resource("s3")
    bucket_list = [x for x in s3.buckets.all() if x.name.endswith("swagger-ui-bucket")]

    if bucket_list:
        bucket_list[0].put_object(Body=swagger_spec, Key="swagger.json")


def generate_api_definitions(parent_swagger):
    """\
    Build an API definition by consolidating information for the various
    lambdas.  For now, just return a hardcoded file present in the source tree,
    but replace symbolic references to the AWS account number with the real
    account number.
    """

    sts = boto3.client("sts")
    aws_account_id = sts.get_caller_identity()["Account"]

    apigateway_integration =  {
        "type": "aws_proxy",
        "uri": "", # to be set later according to the funtions
        "responses": {
        "default": {
            "statusCode": "200"
        }
        },
        "passthroughBehavior": "when_no_match",
        "httpMethod": "POST",
        "contentHandling": "CONVERT_TO_TEXT"
    }

    for key in parent_swagger["paths"]:
        current_dir = key.split(os.sep)[1]
        uri = "arn:aws:apigateway:us-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:us-west-2:"+aws_account_id+":function:"+current_dir+"/invocations"
        temp = apigateway_integration.copy()
        temp["uri"]=uri
        parent_swagger["paths"][key]["x-amazon-apigateway-integration"]=temp

    with open("../api.json", "w") as fp:
        json.dump(parent_swagger, fp, indent=2)

    return open("../api.json").read()


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
    swagger = generate_swagger() # returns [bytes, dictionary]
    # upload_swagger_json(swagger['bytes']) # bytes used in uploading to S3

    # # Update the API Gateway specification
    api_definitions = generate_api_definitions(swagger['dictionary']) # dictionary used in api definition 
    # update_apigateway(api_definitions)