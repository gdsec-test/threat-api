#!/bin/bash

zip -9r function.zip hello.py

# The following section will be replaced by generic code that iterates through
# all of the lambda functions; for now, the following code will create or
# update the lambda as appropriate.

aws lambda get-function --function-name hello > /dev/null 2>&1
RC="$?"

if [ "${RC}" != "0" ]; then
    ROLE_ARN=$(aws iam get-role --output=text --role-name threattools-custom-ThreatRole --query 'Role.Arn')

    aws lambda create-function \
        --function-name hello \
        --runtime python3.7 \
        --role ${ROLE_ARN} \
        --region us-west-2 \
        --timeout 3 \
        --memory-size 128 \
        --handler hello.handler \
        --zip-file fileb://function.zip

    # Add the permission so that the API Gateway can invoke the lambda function

    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    API_GATEWAY_ID=$(aws apigateway get-rest-apis --query 'items[?name==`ThreatAPI`].id' --output text)

    aws lambda add-permission \
        --function-name hello \
        --action lambda:InvokeFunction \
        --statement-id apigateway-1 \
        --principal apigateway.amazonaws.com \
        --source-arn "arn:aws:execute-api:us-west-2:${AWS_ACCOUNT_ID}:${API_GATEWAY_ID}/*/GET/hello"

    aws lambda add-permission \
        --function-name hello \
        --action lambda:InvokeFunction \
        --statement-id apigateway-2 \
        --principal apigateway.amazonaws.com \
        --source-arn "arn:aws:execute-api:us-west-2:${AWS_ACCOUNT_ID}:${API_GATEWAY_ID}/*/GET/hello/*"

else
    aws lambda update-function-code \
        --function-name hello \
        --zip-file fileb://function.zip

fi
