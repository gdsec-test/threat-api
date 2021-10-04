#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name zerobounce --zip-file fileb://function.zip