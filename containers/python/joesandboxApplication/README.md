# Joe Sandbox

## Local Development and Testing

To run the dockerfile locally for development and testing, first login to the AWS Threat Tools DEV-PRIVATE account from your IDE's terminal:

`eval $(aws-okta-processor authenticate -d 7200 -e -o godaddy.okta.com -u YOUR_GD_USERNAME_HERE -k okta)`

Login to be able to fetch Golden Container Image (GCI):

`aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 764525110978.dkr.ecr.us-west-2.amazonaws.com`

Build Docker image:

`docker build -t joesandbox:latest .`

Run Docker image:

`docker run  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -it -d joesandbox`

## Deployments

Deployments to the AWS Dev and Prod Threat Tools environments will be done using our CICD pipelines which can be found in the `.github/workflows/` folder.
