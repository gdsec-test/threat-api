#!/bin/bash

set -eu

env GOPRIVATE=github.secureserver.net,github.com GOOS=linux GOARCH=amd64 go build
rm -f function.zip
zip -9 function.zip manager
