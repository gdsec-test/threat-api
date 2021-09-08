#!/bin/bash

set -eu

rm -f function.zip

pip install --target tempdeps -r requirements.txt
cd tempdeps
zip -r ../function.zip .

cd ..
zip -g function.zip trustar-isac.py enums.py event.py logger.py