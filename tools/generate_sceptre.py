#!/usr/bin/env python3

# This script rebuilds the sceptre configuration and template files for the
# service lambdas using templates.

import json
import logging

from os import listdir
from os.path import dirname, exists, join, realpath
from textwrap import dedent, indent

# Generate the path to the apis and sceptre directories relative to this script
APIS_PATH = realpath(join(dirname(__file__), "..", "apis"))
SCEPTRE_PATH = realpath(join(dirname(__file__), "..", "sceptre"))

CF_CONFIG_START = dedent(
    """\
    template_path: CF-ServiceLambdas.yaml
    dependencies:
      - {{environment}}/{{region}}/CF-CoreResources.yaml
    parameters:
    """
)

SC_CONFIG_START = dedent(
    """\
    template_path: SC-ServiceLambdas.yaml
    dependencies:
      - {{environment}}/{{region}}/SC-CoreResources.yaml
    parameters:
      SSOHost: {{sso_host}}
    """
)

CONFIG_ENTRY = dedent(
    """\
    __NAME__SHA1: !file_contents resources/__NAME__.sha1
    """
)

CONFIG_END = dedent(
    """\
    hooks:
      before_create:
        - !cmd resources/build-service-lambdas.sh
        - !cmd resources/log-group-create.py
      after_create:
        - !cmd rm -f resources/*.sha1
      before_update:
        - !cmd resources/build-service-lambdas.sh
        - !cmd resources/log-group-create.py
      after_update:
        - !cmd rm -f resources/*.sha1
    """
)

TEMPLATE_HEADER = dedent(
    """\
    AWSTemplateFormatVersion: 2010-09-09
    Description: ThreatTools API Service Lambdas
    """
)

CF_PARAMETERS_BLOCK = dedent(
    """\
    __NAME__SHA1:
      Type: String
      Description: SHA1 hash of the __NAME__ lambda source
      Default: ""
    """
)

CF_RESOURCES_BLOCK = dedent(
    """\
    __NAME__LambdaFunction:
      Type: AWS::Lambda::Function
      Properties:
        Code:
          S3Bucket: !Sub gd-threattools-${AWS::AccountId}-code-bucket
          S3Key: !Sub __NAME__/${__NAME__SHA1}
        Description: !Sub __NAME__ lambda (${__NAME__SHA1})
        FunctionName: __NAME__
        Handler: __HANDLER__
        MemorySize: __MEMORYSIZE__
        Role: !Sub arn:aws:iam::${AWS::AccountId}:role/threattools-custom-ThreatRole
        Runtime: __RUNTIME__
        Timeout: __TIMEOUT__

    __NAME__LambdaPermission:
      DependsOn: __NAME__LambdaFunction
      Type: AWS::Lambda::Permission
      Properties:
        Action: lambda:InvokeFunction
        FunctionName: !Sub arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:__NAME__
        Principal: sns.amazonaws.com
        SourceArn: !Sub arn:aws:sns:${AWS::Region}:${AWS::AccountId}:JobRequests

    __NAME__SNSSubscription:
      DependsOn: __NAME__LambdaFunction
      Type: AWS::SNS::Subscription
      Properties:
        Endpoint: !GetAtt __NAME__LambdaFunction.Arn
        Protocol: lambda
        TopicArn: !Sub arn:aws:sns:${AWS::Region}:${AWS::AccountId}:JobRequests

    __NAME__LambdaEventInvokeConfig:
      DependsOn: __NAME__LambdaFunction
      Type: AWS::Lambda::EventInvokeConfig
      Properties:
        DestinationConfig:
          OnSuccess:
            Destination: !Sub arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:JobResponses
          OnFailure:
            Destination: !Sub arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:JobFailures
        FunctionName: __NAME__
        Qualifier: $LATEST

    __NAME__LambdaMetadata:
      Type: AWS::SSM::Parameter
      Properties:
        Name: /ThreatTools/Modules/__NAME__
        Type: String
        Value: '__METADATA__'
    """
)

SC_PARAMETERS_HEADER = dedent(
    """\
    Parameters:
      DevelopmentTeam:
        Type: AWS::SSM::Parameter::Value<String>
        Description: SSM Parameter for team owning the created resources.
        Default: /AdminParams/Team/Name
        AllowedValues:
          - /AdminParams/Team/Name
      DevelopmentEnvironment:
        Type: AWS::SSM::Parameter::Value<String>
        Description: SSM Parameter for development environment this will live in.
        Default: /AdminParams/Team/Environment
        AllowedValues:
          - /AdminParams/Team/Environment
      SSOHost:
        Type: String
        Description: SSO endpoint used by the Authorizer lambda
        Default: "sso.gdcorp.tools"
      DXVpcSecurityGroups:
        Type: AWS::SSM::Parameter::Value<String>
        Description: SSM Parameter for private dx app security group id
        Default: /AdminParams/VPC/PrivateDXAPPSG
        AllowedValues:
          - /AdminParams/VPC/PrivateDXAPPSG
      DXVpcSubnetIds:
        Type: AWS::SSM::Parameter::Value<List<String>>
        Description: SSM Parameter for private dx app subnet ids
        Default: /AdminParams/VPC/DXAPPSubnets
        AllowedValues:
          - /AdminParams/VPC/DXAPPSubnets
    """
)

SC_PARAMETERS_BLOCK = dedent(
    """\
    __NAME__SHA1:
      Type: String
      Description: SHA1 hash of the __NAME__ lambda source
      Default: ""
    """
)

SC_RESOURCES_BLOCK = dedent(
    """\
    __NAME__LambdaFunction:
      Type: AWS::ServiceCatalog::CloudFormationProvisionedProduct
      Properties:
        ProductName: Lambda
        ProvisioningArtifactName: 2.3.0
        ProvisionedProductName: __NAME__LambdaFunction
        ProvisioningParameters:
          - Key: S3Bucket
            Value: !Sub gd-${DevelopmentTeam}-${DevelopmentEnvironment}-code-bucket
          - Key: S3Key
            Value: !Sub __NAME__/${__NAME__SHA1}
          - Key: Handler
            Value: __HANDLER__
          - Key: LambdaName
            Value: __NAME__
          - Key: LambdaDescription
            Value: !Sub __NAME__ lambda (${__NAME__SHA1})
          - Key: MemorySize
            Value: __MEMORYSIZE__
          - Key: Runtime
            Value: __RUNTIME__
          - Key: Timeout
            Value: __TIMEOUT__
          - Key: CustomIAMRoleNameSuffix
            Value: ThreatRole
          - Key: EnvironmentVariablesJson
            Value: !Sub '{"SSO_HOST": "${SSOHost}"}'
          - Key: VpcSecurityGroups
            Value: !Ref DXVpcSecurityGroups
          - Key: VpcSubnetIds
            Value: !Join [ ",", !Ref DXVpcSubnetIds ]
        Tags:
          - Key: doNotShutDown
            Value: true

    __NAME__LambdaPermission:
      DependsOn: __NAME__LambdaFunction
      Type: AWS::ServiceCatalog::CloudFormationProvisionedProduct
      Properties:
        ProductName: LambdaPermission
        ProvisioningArtifactName: 1.0.1
        ProvisionedProductName: __NAME__LambdaPermission
        ProvisioningParameters:
          - Key: Action
            Value: lambda:InvokeFunction
          - Key: FunctionName
            Value: !Sub arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:__NAME__
          - Key: Principal
            Value: sns.amazonaws.com
          - Key: SourceArn
            Value: !Sub arn:aws:sns:${AWS::Region}:${AWS::AccountId}:JobRequests
        Tags:
          - Key: doNotShutDown
            Value: true

    __NAME__SNSSubscription:
      DependsOn: __NAME__LambdaFunction
      Type: AWS::ServiceCatalog::CloudFormationProvisionedProduct
      Properties:
        ProductName: SNSSubscription
        ProvisioningArtifactName: 1.0.1
        ProvisionedProductName: __NAME__SNSSubscription
        ProvisioningParameters:
          - Key: Protocol
            Value: lambda
          - Key: TopicArn
            Value: !Sub arn:aws:sns:${AWS::Region}:${AWS::AccountId}:JobRequests
          - Key: Endpoint
            Value: !Sub arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:__NAME__
          - Key: Region
            Value: !Sub ${AWS::Region}
        Tags:
          - Key: doNotShutDown
            Value: true

    __NAME__LambdaEventInvokeConfig:
      DependsOn: __NAME__LambdaFunction
      Type: AWS::Lambda::EventInvokeConfig
      Properties:
        DestinationConfig:
          OnSuccess:
            Destination: !Sub arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:JobResponses
          OnFailure:
            Destination: !Sub arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:JobFailures
        FunctionName: __NAME__
        Qualifier: $LATEST

    __NAME__LambdaMetadata:
      Type: AWS::SSM::Parameter
      Properties:
        Name: /ThreatTools/Modules/__NAME__
        Type: String
        Value: '__METADATA__'

    __NAME__AppSecSubscriptionFilter:
      DependsOn: __NAME__LambdaFunction
      Type: AWS::ServiceCatalog::CloudFormationProvisionedProduct
      Properties:
        ProductName: SubscriptionFilterAppSecurity
        ProvisionedProductName: __NAME__AppSecSubscriptionFilter
        ProvisioningArtifactName: 1.0.1
        ProvisioningParameters:
            - Key: CloudWatchLogGroup
              Value: /aws/lambda/__NAME__
        Tags:
            - Key: doNotShutDown
              Value: "true"
    """
)

log = logging.getLogger()
log.setLevel(logging.INFO)


def get_lambda_configs():
    """\
    Read the lambda configuration files (lambda.json files in each directory
    under apis/) and store in a dictionary to facilitate later substitutions in
    templates.
    """

    lambda_dict = {}

    for lambda_name in listdir(APIS_PATH):
        try:
            lambda_json_file = join(APIS_PATH, lambda_name, "lambda.json")
            if exists(lambda_json_file):
                lambda_json = json.loads(open(lambda_json_file).read())
                lambda_dict[lambda_name] = {
                    "__NAME__": lambda_name,
                    "__HANDLER__": lambda_json["handler"],
                    "__MEMORYSIZE__": lambda_json["memory-size"],
                    "__RUNTIME__": lambda_json["runtime"],
                    "__TIMEOUT__": lambda_json["timeout"],
                    "__METADATA__": json.dumps(lambda_json.get("metadata", {})),
                }

        except Exception:
            log.exception("Lambda %s has an invalid configuration:", lambda_name)

    return lambda_dict


def expand_template(template, parameters=None, indentation=0):
    """\
    Perform string replacements on `template`, using items in the `parameters`
    dictionary, and indenting the final result by `indentation` number of
    spaces.
    """

    result = template
    for param in parameters.keys():
        result = result.replace(param, parameters[param])

    return indent(result, " " * indentation)


lambdas = get_lambda_configs()

# Generate CF (native Cloud Formation) templates

cf_config = CF_CONFIG_START
for fn in sorted(lambdas.keys()):
    cf_config += expand_template(CONFIG_ENTRY, lambdas[fn], 2)
cf_config += CONFIG_END

open(
    join(SCEPTRE_PATH, "config", "personal", "us-west-2", "CF-ServiceLambdas.yaml"), "w"
).write(cf_config.strip() + "\n")

cf_template = TEMPLATE_HEADER

if lambdas:
    cf_template += "\nParameters:\n"
    for fn in sorted(lambdas.keys()):
        cf_template += expand_template(CF_PARAMETERS_BLOCK, lambdas[fn], 2)

    cf_template += "\nResources:\n"
    for fn in sorted(lambdas.keys()):
        cf_template += expand_template(CF_RESOURCES_BLOCK, lambdas[fn], 2)
        cf_template += "\n"

open(join(SCEPTRE_PATH, "templates", "CF-ServiceLambdas.yaml"), "w").write(
    cf_template.strip() + "\n"
)

# Generate SC (Service Catalog) templates

sc_config = SC_CONFIG_START
for fn in sorted(lambdas.keys()):
    sc_config += expand_template(CONFIG_ENTRY, lambdas[fn], 2)
sc_config += CONFIG_END

for environment in ["dev-private", "dev", "prod"]:
    open(
        join(
            SCEPTRE_PATH, "config", environment, "us-west-2", "SC-ServiceLambdas.yaml"
        ),
        "w",
    ).write(sc_config.strip() + "\n")

sc_template = TEMPLATE_HEADER

if lambdas:
    sc_template += "\n" + SC_PARAMETERS_HEADER
    for fn in sorted(lambdas.keys()):
        sc_template += expand_template(SC_PARAMETERS_BLOCK, lambdas[fn], 2)

    sc_template += "\nResources:\n"
    for fn in sorted(lambdas.keys()):
        sc_template += expand_template(SC_RESOURCES_BLOCK, lambdas[fn], 2)
        sc_template += "\n"

open(join(SCEPTRE_PATH, "templates", "SC-ServiceLambdas.yaml"), "w").write(
    sc_template.strip() + "\n"
)
