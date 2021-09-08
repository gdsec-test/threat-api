#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name trustar --zip-file fileb://function.zip
