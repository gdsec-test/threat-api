# this script builds and deploys docker image for running (Golang so far) ECS Task
# build.sh should be called from it's directory with next arguments:
# first - folder where Go module contained
# second - name of application (and image tag) to run
# third - AWS Account number (development environment)


# build golang application binary, all private repos access should be setup to install depencencies (see docs/development/local-setup.md)
APP_FOLDER=$1
APPLICATION_NAME=$2
AWS_ACCOUNT=$3
pushd .
cd $APP_FOLDER
set -eu
go get ./...
# GOOS is set to Linux, but for Mac OS local development it shoul be GOOS=darwin
env GOPRIVATE=github.secureserver.net,github.com/gdcorp-* GOOS=linux GOARCH=amd64 go build -o $APPLICATION_NAME
popd

# build docker image and deploy to remote ECR (AWS Creds should be set)
AWS_REPO=$AWS_ACCOUNT.dkr.ecr.us-west-2.amazonaws.com
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 764525110978.dkr.ecr.us-west-2.amazonaws.com
docker build -t $AWS_REPO/api-ecstask:$APPLICATION_NAME --build-arg APP_FOLDER=$APP_FOLDER --build-arg APPLICATION_NAME=$APPLICATION_NAME .
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin $AWS_REPO
docker push $AWS_REPO/api-ecstask:$APPLICATION_NAME
# possibly update cluster\task with new image to pick up
# aws ecs update-service --cluster threat-ui-tenet-cluster --service threat-ui-tenet-fargate-service --force-new-deployment --region us-west-2

# clean up built application binary
pushd .
cd $APP_FOLDER
rm -irf $APPLICATION_NAME
popd
