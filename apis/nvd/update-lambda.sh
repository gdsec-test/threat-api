#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name nvd --zip-file fileb://function.zip
