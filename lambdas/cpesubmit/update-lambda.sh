#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name cpesubmit --zip-file fileb://function.zip
