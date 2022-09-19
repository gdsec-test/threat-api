#!/bin/bash

rm -f function.zip
rm -f -r tempdeps

pip install --target tempdeps -r requirements.txt
cd tempdeps
zip -qr ../function.zip .

cd ..
zip -qg function.zip main.py logger.py
