export PYTHON_ARTIFACTORY_USER=$(aws secretsmanager get-secret-value --secret-id python_creds --query SecretString --output text | jq -r .user)
export PYTHON_ARTIFACTORY_PASS=$(aws secretsmanager get-secret-value --secret-id python_creds --query SecretString --output text | jq -r .pass)
touch $VIRTUAL_ENV/pip.conf
cat > $VIRTUAL_ENV/pip.conf <<EOF
[global]
index-url = https://pypi.python.org/simple
trusted-host = pypi.python.org
              artifactory.secureserver.net
extra-index-url= https://$PYTHON_ARTIFACTORY_USER:$PYTHON_ARTIFACTORY_PASS@artifactory.secureserver.net/artifactory/api/pypi/python-virt/simple
EOF
