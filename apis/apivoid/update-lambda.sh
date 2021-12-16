#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name apivoid --zip-file fileb://function.zip
