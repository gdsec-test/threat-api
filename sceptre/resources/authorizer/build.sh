#!/bin/bash

# this script builds and deploys authorizer lambda into to AWS account
# auth into proper AWS account

rm -rf package
mkdir package
cp ./index.py package
cp ./Dockerfile package
pushd package

export PYTHON_ARTIFACTORY_USER=$(aws secretsmanager get-secret-value --secret-id python_creds --query SecretString --output text | jq -r .user)
export PYTHON_ARTIFACTORY_PASS=$(aws secretsmanager get-secret-value --secret-id python_creds --query SecretString --output text | jq -r .pass)

python -m venv venv
source venv/bin/activate
touch $VIRTUAL_ENV/pip.conf
cat > $VIRTUAL_ENV/pip.conf <<EOF
[global]
index-url = https://pypi.python.org/simple
trusted-host = pypi.python.org
               artifactory.secureserver.net
extra-index-url= https://$PYTHON_ARTIFACTORY_USER:$PYTHON_ARTIFACTORY_PASS@artifactory.secureserver.net/artifactory/api/pypi/python-virt/simple
EOF

docker build --progress plain  --rm --build-arg AWS_ACCESS_KEY_ID --build-arg AWS_SECRET_ACCESS_KEY --build-arg AWS_SESSION_TOKEN --build-arg AWS_REGION=us-west-2 -t authorizerlambdaimage .
docker run --rm -it -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_REGION=us-west-2  authorizerlambdaimage

popd
