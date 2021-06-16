#!/bin/bash

BUCKET=$(aws s3api list-buckets --output text --query 'Buckets[?ends_with(Name, `swagger-ui-bucket`)].Name')

SWAGGER_UI_VERSION="3.42.0"

mkdir -p swagger-ui-bucket
pushd swagger-ui-bucket

  wget -nv https://github.com/swagger-api/swagger-ui/archive/v${SWAGGER_UI_VERSION}.tar.gz
  tar -xzf v${SWAGGER_UI_VERSION}.tar.gz

  pushd swagger-ui-${SWAGGER_UI_VERSION}/dist

    # Replace default petstore spec with a generic swagger.json reference
    sed -i 's#https://petstore.swagger.io/v2/swagger.json#swagger.json#g' index.html
    aws s3 sync . s3://${BUCKET}

  popds

popd
rm -rf swagger-ui-bucket

aws s3 cp resources/swagger.json s3://${BUCKET}/swagger.json
