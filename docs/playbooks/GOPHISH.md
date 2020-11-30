# GoPhish

[Gophish](https://github.secureserver.net/threat/threat-tools#GoPhish) is currently hosted on-prem but will be moved to AWS. This document describes handling and response to the AWS architecture.

## Web application problems

1. Diagnose
    * Search through any and all logs and error messages.  Logs will be shipped to our production ELK instance (link TBD)
2. Fix
    * Once you have an understanding of the problem, optionally fix, restart, or dig deeper on the issue.
    * You may attempt restarting the docker container, or restarting the AWS RDS database.

## Database problems

Most database problems are probably a results of gophish being updates and having an invalid schema, or the aws RDS is unavailable to gophish...TODO.
