# this Dockerfile is needed to test, build and deploy authorizer lambda to AWS account
# prereqs: copy pip.conf to current directory from origin where you have it and auth into proper AWS account, then use below commands to run
# cp ~/.pip/pip.conf .
# docker build --rm --build-arg VIRTUAL_ENV=. -t authorizerlambdaimage .
# docker run --rm -it -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_REGION=us-west-2  authorizerlambdaimage

FROM lambci/lambda:build-python3.7

COPY . .

RUN cp venv/pip.conf /etc/pip.conf
RUN pip install gd-auth --target .

ENV AWS_DEFAULT_REGION us-west-2

RUN rm -f function.zip
RUN zip -9qrg function.zip .

CMD aws lambda update-function-code --function-name authorizer --zip-file fileb://function.zip
