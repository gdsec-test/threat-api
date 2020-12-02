# GoPhish

[Gophish](https://github.secureserver.net/threat/threat-tools#GoPhish) is currently hosted on-prem but will be moved to AWS. This document describes handling and response to the AWS architecture.

## Web application problems

To find details on the problem, follow these steps

1. Diagnose

* Search through any and all logs and error messages. Logs will be shipped to our production ELK instance
* Look at in-browser logs or errors that could be clues to a client side error
* Check if there is a new version of gophish we should update to
* Check to make sure the database is online an accessible (logs may point towards this)

2. Fix

Once you have an understanding of the problem, optionally fix, restart, or dig deeper on the issue.

You may attempt restarting the docker container, or restarting the AWS RDS database.

## Database problems

To diagnose a database problem, first make sure it is online and accessible.  If it is, check gophish logs (see previous section) to find any details on a specific issue.

Most database problems are probably a results of gophish being updates and having an invalid schema, or the aws RDS is unavailable to gophish.
