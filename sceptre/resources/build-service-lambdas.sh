#!/bin/bash

# This script supports the build process for the service lambdas:
# - Store a SHA1 hash of the source code so the CloudFormation templates can
#   use them to detect differences and trigger an update
# - Build the lambdas
# - Create ZIP files and upload them to S3 so that the CloudFormation templates
#   can reference them

set -eu

THREAT_API_SOURCE=$(cd `dirname $0`/../.. && pwd)

CODE_BUCKET=$(aws s3api list-buckets --output text --query 'Buckets[?ends_with(Name, `code-bucket`)].Name')
RESOURCES_DIR=${THREAT_API_SOURCE}/sceptre/resources
SERVICE_LAMBDAS=$(ls ${THREAT_API_SOURCE}/apis)

for LAMBDA in ${SERVICE_LAMBDAS}
do
    echo Building ${LAMBDA} lambda

    pushd ${THREAT_API_SOURCE}/apis/${LAMBDA}

    if [ -x "build.sh" ]; then

        # Build the lambda using the supplied build script
        ./build.sh

        # Store the SHA1 hash of the source directory
        SHA1HASH=$(shasum function.zip | cut -d' ' -f1)
        echo ${SHA1HASH} > ${RESOURCES_DIR}/${LAMBDA}.sha1

        # Upload the ZIP file to S3
        aws s3 cp function.zip s3://${CODE_BUCKET}/${LAMBDA}/${SHA1HASH}

        # Cleanup
        rm -f ${LAMBDA} function.zip
    fi

    popd

done
