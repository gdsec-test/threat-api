#!/bin/bash

set -eu
env GOPRIVATE=github.secureserver.net,github.com/gdcorp-* GOOS=linux GOARCH=amd64 go build -o shodan
rm -f function.zip
zip -9q function.zip shodan
