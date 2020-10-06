# Environment Setup

### Python Environment

1. Create and activate a python3 virtual environment with modules listed in the
   `requirements.txt` file:

   ```
   python3 -m venv sceptre
   source sceptre/bin/activate
   pip install -U pip
   pip install -U -r requirements.txt
   ```

1. Activate the virtualenv:

   ```
   source sceptre/bin/activate
   ```

1. Authenticate using the service account:

   * Login with your Jomax credentials by following the directions
     [here](https://github.com/godaddy/aws-okta-processor).

     To manually obtain an assumed role for your Jomax account:

     ```
     eval $(aws-okta-processor authenticate -d 7200 -e -o godaddy.okta.com -u ${USER} -k okta')
     ```

   * Verify your current role:

     ```
     aws sts get-caller-identity
     ```

   * Obtain an assumed deployment role using the deploy user credentials from
     SecretsManager:

     ```
     DEPLOY_USER=$(aws secretsmanager get-secret-value \
                       --secret-id /Secrets/IAMUser/GD-AWS-DeployUser-ThreatTools-Dev-Private \
                       --query SecretString \
                       --output text)

     export AWS_ACCESS_KEY_ID="$(echo $DEPLOY_USER | jq -r .AccessKeyId)"
     export AWS_SECRET_ACCESS_KEY="$(echo $DEPLOY_USER | jq -r .SecretAccessKey)"
     export AWS_DEFAULT_REGION="us-west-2"
     unset AWS_SESSION_TOKEN

     DEPLOY_ROLE=$(aws sts assume-role \
                       --role-arn arn:aws:iam::345790377847:role/GD-AWS-USA-GD-ThreatTools-Dev-Private-Deploy \
                       --role-session-name $(git config user.email) \
                       --output text \
                       --query '[Credentials.AccessKeyId, Credentials.SecretAccessKey, Credentials.SessionToken]')

     export AWS_ACCESS_KEY_ID=$(echo ${DEPLOY_ROLE} | cut -d' ' -f1)
     export AWS_SECRET_ACCESS_KEY=$(echo ${DEPLOY_ROLE} | cut -d' ' -f2)
     export AWS_SESSION_TOKEN=$(echo ${DEPLOY_ROLE} | cut -d' ' -f3)
     ```

   * Verify you now have the deployment role:

     ```
     aws sts get-caller-identity
     ```

### AWS Certificate Manager (ACM) Setup

1. Use [Cloud UI](https://cloud.int.godaddy.com/security/certs) to request a
   certificate for the FQDN to be used, such as `api-dev.threat.gdcorp.tools`.

1. Download the certificate, private key, and certificate chain from Cloud UI
   to your local workstation.

1. Run the following using the deployment role, such as
   `GD-AWS-USA-GD-ThreatTools-Dev-Private-Deploy`:

   ```
   aws acm import-certificate \
       --certificate file://api-dev.threat.gdcorp.tools.crt \
       --private-key file://api-dev.threat.gdcorp.tools.key \
       --certificate-chain file://api-dev.threat.gdcorp.tools_intermediate_chain.crt
   ```

1. Delete the downloaded copies of the certificate, private key, and
   certificate chain from your local workstation.

1. Note the UUID contained in the `CertificateArn` that is displayed when the
   certificate is imported.  This value should match that specified by
   `certificate_id` in the Sceptre configuration file for the current
   environment:

   ```
   {
       "CertificateArn": "arn:aws:acm:us-west-2:345790377847:certificate/21f37efe-2ead-4e84-93c1-4c707b96d00d"
   }
   ```

### Sceptre / CloudFormation / Service Catalog

Run sceptre to configure the AWS account (substituting the appropriate
environment):

```
sceptre launch dev-private/us-west-2
```

### Update DNS CNAME Entry

1. Use [Cloud UI](https://cloud.int.godaddy.com/networking/dnsrecords) to
   create or update a `CNAME` DNS record for the specified FQDN that points to
   the `regionalDomainName` of the newly created API gateway.  The target of
   the CNAME record should match the output of:

   ```
   aws apigateway get-domain-name \
       --domain-name api-dev.threat.gdcorp.tools \
       --query regionalDomainName \
       --output text
   ```

