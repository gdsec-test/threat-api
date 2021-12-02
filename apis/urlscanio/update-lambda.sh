#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name urlscanio --zip-file fileb://function.zip