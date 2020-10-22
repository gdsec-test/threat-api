# ThreatTools API Development

### AWS Accounts

All AWS accounts are in the us-west-2 (Oregon) region.

| AWS Account | API Endpoint | Environment | Description
| --- | --- | --- | ---
| 345790377847 | https://api-dev.threat.gdcorp.tools | dev-private | Account for active development (non-CICD)
| TBD | TBD | dev | Account for active development (CICD)
| TBD | https://api.threat.gdcorp.tools | prod | Production account (CICD)

### Authentication

* All endoints behind the API gateway require a valid JWT (although this
  validation currently does not include verifying the age of the JWT, or the
  authorization decision)

* [THREAT-487](https://jira.godaddy.com/browse/THREAT-487) will enforce a
  maximum JWT age of 60 days by replacing the default JWTAuthorizer

* [THREAT-486](https://jira.godaddy.com/browse/THREAT-486) will provide a
  library which individual APIs can use to verify JWT age

### JWTs

To obtain a JWT, you can use the [jwt.py](../tools/jwt.py) script.  The script
will prompt for a username and password, and then print out the JWT.

You may then pass this JWT to the ThreatTools API by setting the
`Authorization` header, using browser tools such as
[ModHeader](https://bewisse.com/modheader/).  The value of the header field
should be `sso-jwt` followed by the JWT, separated by a space character.

### Authorization

* You can use the [util lambda](https://github.secureserver.net/threat/util/tree/master/lambda) tools to check authorization in individual lambdas (using a specified list of JOMAX AD groups).

### Standards / Best Practices

* Development of the ThreatTools API will follow the [CTO
  Guidelines](https://github.secureserver.net/CTO/guidelines/blob/master/Standards-Best-Practices/MustHaveShouldDo.md)
  for applications that are onboarding to AWS.  Alternative formatted document
  is
  [here](https://confluence.godaddy.com/display/AS/Phase+3+-+Must+Haves+to+go+to+Public+cloud).

* [GoDaddy API Design Standards](https://github.secureserver.net/CTO/guidelines/tree/master/api-design)

* [Best practices for REST API design](https://stackoverflow.blog/2020/03/02/best-practices-for-rest-api-design/)

* [Asynchronous REST operations](https://restcookbook.com/Resources/asynchroneous-operations/)

* [Tracing Fields](https://www.elastic.co/guide/en/ecs/current/ecs-tracing.html)

### Python Virtual Environment

A Python virtual environment is needed for tools like
[Sceptre](../sceptre/README.md), [Tartufo](#tartufo), and the [sample jwt.py
tool](../tools/jwt.py).

To create a Python virtual environment:

```bash
python3 -m venv ~/.threatvenv
source ~/.threatvenv/bin/activate
pip install -U pip
pip install -U -r requirements.txt -r requirements-test.txt
```

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
