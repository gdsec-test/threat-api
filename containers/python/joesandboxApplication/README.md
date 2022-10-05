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

Deployments to the AWS Dev and Prod Threat Tools environments will be done using our CICD pipelines which can be found in the `.github/workflows/` folder. Uploading container image (dockerfile) to ECR is done via the CICD deployment pipelines in our Threat Tools Dev and Prod environments.

## Upload Container Image to the AWS ECR Joe Sandbox Repo

The Amazon ECR repository is called `joesandbox`. Execute the following commands to upload the dockerfile to this ECR repo:

`aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 345790377847.dkr.ecr.us-west-2.amazonaws.com`

Login to be able to fetch Golden Container Image (GCI):

`aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 764525110978.dkr.ecr.us-west-2.amazonaws.com`

Build Docker image:

`docker build -t joesandbox .`

Tag image as latest:

`docker tag joesandbox:latest 345790377847.dkr.ecr.us-west-2.amazonaws.com/joesandbox:latest`

Push image to the ECR repo:

`docker push 345790377847.dkr.ecr.us-west-2.amazonaws.com/joesandbox:latest`
