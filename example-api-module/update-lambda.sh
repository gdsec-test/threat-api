#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name example --zip-file fileb://function.zip
