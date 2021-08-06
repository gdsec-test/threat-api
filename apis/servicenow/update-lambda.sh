#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name servicenow --zip-file fileb://function.zip
