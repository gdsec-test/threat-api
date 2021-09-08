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
