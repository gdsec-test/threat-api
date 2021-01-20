# ThreatTools API

![Code quality check](https://github.com/gdcorp-infosec/threat-api/workflows/Code%20quality%20check/badge.svg)
![ThreatAPI Deployment (DEV)](https://github.com/gdcorp-infosec/threat-api/workflows/ThreatAPI%20Deployment%20(DEV)/badge.svg)

This repository contains documentation, infrastructure configuration scripts,
and API implementations for the ThreatTools API hosted on AWS.

### Environments

| Environment | URL (Swagger Link)                                                                                                                  | Description                               |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| DEV-PRIVATE | [api-private.threat.int.dev-gdcorp.tools](https://sso.dev-gdcorp.tools/login?realm=jomax&app=api-private.threat.int&path=/swagger/) | Account for active development (non-CICD) |
| DEV         | [api.threat.int.dev-gdcorp.tools](https://sso.dev-gdcorp.tools/login?realm=jomax&app=api.threat.int&path=/swagger/)                 | Account for active development (CICD)     |
| PROD        | [api.threat.int.gdcorp.tools](https://sso.gdcorp.tools/login?realm=jomax&app=api.threat.int&path=/swagger/)                         | Production account (CICD)                 |

### Documentation

* [API Usage](docs/USAGE.md)
* [Development Guidelines](docs/DEVELOPMENT.md)
* [Repository Organization](docs/ORGANIZATION.md)
* [Sceptre Configuration](sceptre/README.md)
* [Architecture](docs/ARCHITECTURE.md)

### Tools

* [Miscellaneous Tools](tools/README.md)

### Links

* Add links (Confluence, GitHub repos) here
