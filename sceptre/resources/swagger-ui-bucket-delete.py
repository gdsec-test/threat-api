#!/usr/bin/env python

# The following AWS CLI command doesn't account for buckets with versioning
# BUCKET=$(aws s3api list-buckets --output text --query 'Buckets[?ends_with(Name, `swagger-ui-bucket`)].Name')
# aws s3 rm s3://${BUCKET}/ --recursive

import boto3

s3 = boto3.resource("s3")
bucket_list = [x for x in s3.buckets.all() if x.name.endswith("swagger-ui-bucket")]

if bucket_list:
    bucket_list[0].object_versions.delete()
