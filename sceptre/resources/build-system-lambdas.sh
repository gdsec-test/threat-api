#!/bin/bash

# This script supports the build process for the system
# ("manager" and "responseprocessor") lambdas:
# - Store a SHA1 hash of the binary so the CloudFormation templates can
#   use them to detect differences and trigger an update
# - Build the lambdas (both are assumed to be golang implementations)
# - Create ZIP files and upload them to S3 so that the CloudFormation templates
#   can reference them

set -eu
sudo apt-get install zip unzip libdigest-sha-perl -qy
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh | bash
source ~/.nvm/nvm.sh

THREAT_API_SOURCE=$(cd `dirname $0`/../.. && pwd)

CODE_BUCKET=$(aws s3api list-buckets --output text --query 'Buckets[?ends_with(Name, `code-bucket`)].Name')
RESOURCES_DIR=${THREAT_API_SOURCE}/sceptre/resources
SYSTEM_LAMBDAS="manager responseprocessor vulnerabilitywatch"

pushd .
cd ${RESOURCES_DIR}/authorizer
./build.sh
popd

for LAMBDA in ${SYSTEM_LAMBDAS}
do
    echo Building ${LAMBDA} lambda

    pushd ${THREAT_API_SOURCE}/lambdas/${LAMBDA}

    # Create ZIP file and upload to S3
    rm -f function.zip

    if test -f "./package.json"; then
        # build NodeJS Lambdas
        nvm install
        nvm use
        npm i
        zip -9rq function.zip .
    else
        # build Golang Lambdas
        env GOPRIVATE=github.secureserver.net,github.com/gdcorp-* GOOS=linux GOARCH=amd64 go build
        zip -9q function.zip ${LAMBDA}
    fi;

    # Store the SHA1 hash of the resulting binary
    SHA1HASH=$(shasum function.zip | cut -d' ' -f1)
    echo ${SHA1HASH} > ${RESOURCES_DIR}/${LAMBDA}.sha1

    aws s3 cp function.zip s3://${CODE_BUCKET}/${LAMBDA}/${SHA1HASH} --quiet

    # Cleanup
    rm -f ${LAMBDA} function.zip

    popd
done
