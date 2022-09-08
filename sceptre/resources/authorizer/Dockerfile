# this Dockerfile is needed to test, build and deploy authorizer lambda to AWS account
# prereqs: copy pip.conf to current directory from origin where you have it and auth into proper AWS account, then use below commands to run
# should be run from ./buid.sh file to work properly

FROM lambci/lambda:build-python3.7

ARG AWS_ACCESS_KEY_ID
ENV AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
ARG AWS_SECRET_ACCESS_KEY
ENV AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
ARG AWS_SESSION_TOKEN
ENV AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN

COPY . .

RUN cp venv/pip.conf /etc/pip.conf
RUN pip install gd-auth --target .

ENV AWS_DEFAULT_REGION us-west-2

RUN rm -f function.zip
RUN zip -9qrg function.zip .

CMD aws lambda update-function-code --function-name authorizer --zip-file fileb://function.zip
