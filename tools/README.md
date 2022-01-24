# Miscellaneous Tools

### Create api module golang
* `create-templates.py`

  Python script using jinja2 to generate the templates for triage modules. Enter
  the module name on inout prompt and the boiler plate code structures are generated.

  The script is for ease of use and gives an easier starting point. It is encouraged to
  not depend on the script on the whole as the module depends a lot on service you are writing.

* `templates`
  The folder contains all the templates required for jinja2 and a generic threat module code


### JWT-related

* `jwt.py`

  Simple script to get a JWT for a JOMAX employee.  Prompts the user for a
  username and password and returns a JWT to stdout.

* `ad_groups.py`

  Simple script to get AD groups for a JWT.  Accepts a JWT as the first
  argument and returns a sorted list of AD groups.

### Sceptre related

* `generate_sceptre.py`

  Script to generate Sceptre config and template files for the service lambdas.
  This script updates sceptre files for discovered lambdas in the `apis/`
  directory.

### Lambda-run

`Lambda-run` is interactive CLI tool to call and debug AWS Lambdas in their native environment on local machine
It is configured to work with our Lambdas and should be run from root folder of project

#### Install:
`npm install -g ./tools/lambda-run/` - in root folder

#### Launch:
1. `lambda-run` - in root folder(some paths set to be relative to root folder)
2. Follow instruction and answer all questions and wait for `Lambda API listening on port 9001...` message in shell

#### Develop and debug:
1. Copy, change as needed and run suggested command (see `info: Use below command to call\debug Lambda:
`) in separate terminal, for instance:
```
aws lambda invoke --endpoint http://localhost:9001 --no-sign-request --function-name apivoid --payload '{"Records":[{"Sns":{"Message":"{\"JobID\":\"test\",\"Submission\":{\"Body\":\"{\\\"Modules\\\":[\\\"apivoid\\\"],\\\"IOCs\\\":[\\\"google.com\\\"],\\\"IOCType\\\":\\\"DOMAIN\\\"}\"}}"}}]}' /dev/stdout 2>/dev/null
```
2. See debug info and output for results
3. Lambda supports watch-mode for Python and NodeJS(Go requires rebuild\re-run), so when you change target code, it will pick latest changes, for the next invoke call fresh code will be used
