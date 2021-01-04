# Miscellaneous Tools

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
