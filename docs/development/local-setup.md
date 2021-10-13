# Local Setup Instructions

## Language specific setup

### Python Virtual Environment

A Python virtual environment is needed for tools like
[Sceptre](../../sceptre/README.md), [Tartufo](#tartufo), and the [sample jwt.py
tool](../../tools/jwt.py).

To create a Python virtual environment, run the following commands from root of the folder:

```bash
python3 -m venv ~/.threatvenv
source ~/.threatvenv/bin/activate
pip install -U pip
pip install -U -r requirements.txt -r requirements-test.txt
```

For any package/ version specific errors, check the latest compatibility available online.
Make sure it's replicated when pulling a virtual environment.

### Go Env setup

Because we rely on internal libraries, you need to configure go to be able to authenticate and download those libraries.

First we need to have git use ssh instead of prompt for user/pass for private repos:

```sh
git config --global url.git@github.secureserver.net:.insteadOf https://github.secureserver.net/
git config --global url.git@github.com:gdcorp-.insteadOf https://github.com/gdcorp-
```

Then if you run `cat ~/.gitconfig` you should see this addition

```sh
> cat ~/.gitconfig
[url "git@github.secureserver.net:"]
        insteadOf = https://github.secureserver.net/
[url "git@github.com:gdcorp-"]
        insteadOf = https://github.com/gdcorp-
```

Then set this env var whenever you run `go get`.  You may even need to run it multiple times if you haven't run it recently.  A good rule of thumb is whenever you are getting a `410 GONE` error, run this command again

```sh
export GOPRIVATE=github.secureserver.net,github.com/gdcorp-*
```


For any package/ version specific errors, check the latest compatibility available online.
`go.mod` and `go.sum` has to be [committed to the codebase with your PR when you add/ modify any packages used](https://github.com/golang/go/wiki/Modules#releasing-modules-all-versions)

## Additional tools needed for development

##### [ If you had set up the python environment, this should be covered in the pip requirements ]

### Tartufo

[Tartufo](https://github.com/godaddy/tartufo) searches through git repositories
for high entropy strings and secrets, digging deep into commit history.  This
utility is used as a git pre-commit hook to avoid checking in such files to
GitHub.

This repository leverages [pre-commit](https://pre-commit.com/) to run various
tests before a git commit can proceed.  The tests are described in the
`.pre-commit-config.yaml` file in the top level directory of this repository.

The pre-commit utility is installed as part of the Python virtual environment
setup described above.

If you've just checked out this repository, you'll need to invoke the following
to install the pre-commit hook in your local git working tree:

```bash
pre-commit install
```

A tartufo scan will be run whenever `git commit` is performed.  To manually run
the pre-commit hooks, use the following command:

```bash
pre-commit run -a
```

##### For Tartufo failures

To exclude particular exceptions within a file rather than the entire file:
- Get the signature from failure
  ![tartufo-signature](../diagrams/tartufo_signature.png)
- Add the signature to file pyproject.toml within exclude-signatures
- Include the reason on why the signature was excluded as a comment next to the signature

##### For failures other than Tartufo
-  pre-commit would have fixed it for you already, try running it again


### Getting your identity with AWS
If your codebase is talking to AWS, you'll need an identity to log into AWS. Follow the below commands to authenticate

##### Authenticate using the service account:
(You can also use your personal account to test, but a deploy role is recommended to gain the same level of access)

* Login with your Jomax credentials by following the directions
  [here](https://github.com/godaddy/aws-okta-processor).

  To manually obtain an assumed role for your Jomax account:

  ```
  eval $(aws-okta-processor authenticate -d 7200 -e -o godaddy.okta.com -u ${USER} -k okta)
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

### Testing modules in local
#### Go:
All your codes are written to run on lambdas.Different ways to test the Lambda code in local:
- Through Unit Tests. As long as your unit tests run, you are good to go
- Using your IDEs features to specifically run the functions in debug mode

#### AWS Components & Swagger
- AWS SAM Local can be used to test them locally. We have tried this earlier when the architecture was small.
  As the architecture grew, it became a time consuming task to replicate the requests and responses to replicate the
  entire architecture to local. A PR is always welcome if you want to get an easier way and maintain it.
- Workarounds with Docker, Event's JSON can used to replicate the working of AWS Lambda to local. Various examples of
  developers working on them can be found easily on internet. Few Egs,
    - [Eg 1](https://medium.com/nagoya-foundation/running-and-debugging-go-lambda-functions-locally-156893e4ed0d)
    - [Eg 2](https://github.com/mtojek/aws-lambda-go-proxy)

- Because of the AWS components involved for processing the results after the lambda returns the results, it is difficult
  to pull the swagger in local. At the time of writing, tests on swagger can be done from dev-private onwards after deployment
