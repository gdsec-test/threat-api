#!/bin/bash

# This script supports the build process for the system
# ("manager" and "responseprocessor") lambdas:
# - Store a SHA1 hash of the source code so the CloudFormation templates can
#   use them to detect differences and trigger an update
# - Build the lambdas (both are assumed to be golang implementations)
# - Create ZIP files and upload them to S3 so that the CloudFormation templates
#   can reference them

set -eu

THREAT_API_SOURCE=$(cd `dirname $0`/../.. && pwd)

CODE_BUCKET=$(aws s3api list-buckets --output text --query 'Buckets[?ends_with(Name, `code-bucket`)].Name')
RESOURCES_DIR=${THREAT_API_SOURCE}/sceptre/resources
SYSTEM_LAMBDAS="manager responseprocessor"

for LAMBDA in ${SYSTEM_LAMBDAS}
do
    echo Building ${LAMBDA} lambda

    pushd ${THREAT_API_SOURCE}/lambdas/${LAMBDA}

    # Store the SHA1 hash of the source code
    SHA1HASH=$(sha1sum "${LAMBDA}.go" | cut -d' ' -f1)
    echo ${SHA1HASH} > ${RESOURCES_DIR}/${LAMBDA}.sha1

    env GOPRIVATE=github.secureserver.net,github.com/gdcorp-* GOOS=linux GOARCH=amd64 go build

    # Create ZIP file and upload to S3
    rm -f function.zip
    zip -9 function.zip ${LAMBDA}
    aws s3 cp function.zip s3://${CODE_BUCKET}/${LAMBDA}/${SHA1HASH}

    # Cleanup
    rm -f ${LAMBDA} function.zip

    popd
done