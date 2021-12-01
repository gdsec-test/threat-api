#!/bin/bash

set -eu

rm -f function.zip

pip install --target tempdeps -r requirements.txt
cd tempdeps
zip -qr ../function.zip .

cd ..
zip -qg function.zip trustar-isac.py enums.py event.py logger.py
