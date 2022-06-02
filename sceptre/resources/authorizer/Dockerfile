# this Dockerfile is needed to test, build and deploy authorizer lambda to AWS account
# prereqs: copy pip.conf to current directory from origin where you have it and auth into proper AWS account, then use below commands to run
# should be run from ./buid.sh file to work properly

FROM lambci/lambda:build-python3.7

COPY . .

RUN cp venv/pip.conf /etc/pip.conf
RUN pip install gd-auth --target .

ENV AWS_DEFAULT_REGION us-west-2

RUN rm -f function.zip
RUN zip -9qrg function.zip .

CMD aws lambda update-function-code --function-name authorizer --zip-file fileb://function.zip
