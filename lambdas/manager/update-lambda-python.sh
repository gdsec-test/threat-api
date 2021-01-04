#!/bin/bash

set -eu

./build-python.sh

aws lambda update-function-code --function-name manager --zip-file fileb://function.zip
