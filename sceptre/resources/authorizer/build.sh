#!/bin/bash

rm -f function.zip

zip -9qr function.zip index.py

# Add the required python modules for this lambda.

rm -rf package
mkdir package
pushd package
pip install git+ssh://git@github.secureserver.net/auth-contrib/PyAuth.git@7.2.2#egg=PyAuth --target .
zip -9qrg ../function.zip .
popd
rm -rf package


aws lambda update-function-code \
    --function-name authorizer \
    --zip-file fileb://function.zip


rm -f function.zip
