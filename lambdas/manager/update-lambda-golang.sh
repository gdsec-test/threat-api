#!/bin/bash

set -eu

./build-golang.sh

aws lambda update-function-code --function-name manager --zip-file fileb://function.zip
