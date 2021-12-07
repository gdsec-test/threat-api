#!/bin/bash

AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BUCKET=$(aws s3api list-buckets --output text --query 'Buckets[?ends_with(Name, `code-bucket`)].Name')

shasum resources/api-setup.json | cut -d' ' -f1 > resources/api.sha1

echo "Uploading API Gateway swagger specification"

sed -e "s:___AWS_ACCOUNT___:$AWS_ACCOUNT:g" resources/api-setup.json | aws s3 cp - s3://${BUCKET}/api-setup.json --quiet
