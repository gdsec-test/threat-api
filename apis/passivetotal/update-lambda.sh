#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name passivetotal --zip-file fileb://function.zip
