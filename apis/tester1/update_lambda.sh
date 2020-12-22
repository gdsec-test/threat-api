#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name tester1 --zip-file fileb://function.zip
