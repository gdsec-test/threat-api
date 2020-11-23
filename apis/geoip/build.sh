#!/bin/bash

if [ ! -f GeoLite2-City.mmdb ]; then
    # Pull last free version of GeoLite2 DB from Fedora archives

    echo "Downloading GeoLite2-City_20191217.tar.gz"

    wget -nv https://src.fedoraproject.org/repo/pkgs/geolite2/GeoLite2-City_20191217.tar.gz/sha512/b90d98901a2906465e69c69d9ddc95a4d5945deba683a856bc858229e9a7358acf46b4e73b131c7bd497ce4029848e1431fc0efb8bfdc417bd3241d9965e2dae/GeoLite2-City_20191217.tar.gz

    tar zxf GeoLite2-City_20191217.tar.gz GeoLite2-City_20191217/GeoLite2-City.mmdb

    rm GeoLite2-City_20191217.tar.gz

    mv GeoLite2-City_20191217/GeoLite2-City.mmdb GeoLite2-City.mmdb

    rmdir GeoLite2-City_20191217
fi

env GOPRIVATE=github.secureserver.net GOOS=linux GOARCH=amd64 go build main.go

zip -9r function.zip main GeoLite2-City.mmdb

# The following section will be replaced by generic code that iterates through
# all of the lambda functions; for now, the following code will create or
# update the lambda as appropriate.

aws lambda get-function --function-name geoip > /dev/null 2>&1
RC="$?"

if [ "${RC}" != "0" ]; then
    ROLE_ARN=$(aws iam get-role --output=text --role-name threattools-custom-ThreatRole --query 'Role.Arn')

    aws lambda create-function \
        --function-name geoip \
        --runtime go1.x \
        --role ${ROLE_ARN} \
        --region us-west-2 \
        --timeout 15 \
        --memory-size 256 \
        --handler main \
        --zip-file fileb://function.zip

    # Add the permission so that the API Gateway can invoke the lambda function

    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    API_GATEWAY_ID=$(aws apigateway get-rest-apis --query 'items[?name==`ThreatAPI`].id' --output text)

    aws lambda add-permission \
        --function-name geoip \
        --action lambda:InvokeFunction \
        --statement-id apigateway \
        --principal apigateway.amazonaws.com \
        --source-arn "arn:aws:execute-api:us-west-2:${AWS_ACCOUNT_ID}:${API_GATEWAY_ID}/gddeploy/*/*"

else
    aws lambda update-function-code \
        --function-name geoip \
        --zip-file fileb://function.zip

fi
