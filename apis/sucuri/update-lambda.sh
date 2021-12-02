#!/bin/bash

set -eu

./build.sh

aws lambda update-function-code --function-name sucuri --zip-file fileb://function.zip
