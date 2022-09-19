#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name tanium --zip-file fileb://function.zip
