# ThreatTools API

![ThreatAPI Deployment (PROD)](https://github.com/gdcorp-infosec/threat-api/workflows/ThreatAPI%20Deployment%20(PROD)/badge.svg)
![ThreatAPI Deployment (DEV)](https://github.com/gdcorp-infosec/threat-api/workflows/ThreatAPI%20Deployment%20(DEV)/badge.svg)
![ThreatAPI Deployment (DEV-PRIVATE)](https://github.com/gdcorp-infosec/threat-api/workflows/ThreatAPI%20Deployment%20(DEV-PRIVATE)/badge.svg)
![Code quality check](https://github.com/gdcorp-infosec/threat-api/workflows/Code%20quality%20check/badge.svg)
![Deploy role secret sync](https://github.com/gdcorp-infosec/threat-api/workflows/Deploy%20Role%20secrets%20automatic%20sync/badge.svg)


This repository contains documentation, infrastructure configuration scripts,
and API implementations for the ThreatTools API hosted on AWS.

### Environments

To access the links below, you will need to be on the VPN, and be in the `PaloAlto-DefaultRoute` Jomax AD group. See [Palo Alto VPN Help Information](https://confluence.godaddy.com/pages/viewpage.action?spaceKey=CORPNET&title=Palo+Alto+VPN+Help+Information) for additional information.


| Environment | URL (Swagger Link)                                                                                                                  | Description                               |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| DEV-PRIVATE | [api-private.threat.int.dev-gdcorp.tools](https://sso.dev-gdcorp.tools/login?realm=jomax&app=api-private.threat.int&path=/swagger/) | Account for active development (non-CICD) |
| DEV         | [api.threat.int.dev-gdcorp.tools](https://sso.dev-gdcorp.tools/login?realm=jomax&app=api.threat.int&path=/swagger/)                 | Account for active development (CICD)     |
| PROD        | [api.threat.int.gdcorp.tools](https://sso.gdcorp.tools/login?realm=jomax&app=api.threat.int&path=/swagger/)                         | Production account (CICD)                 |

### Documentation

* [API Usage](docs/IOCTYPES.md)
* [Development Guidelines](docs/development/threat-developer-guide.md)
* [Repository Organization](docs/ORGANIZATION.md)
* [Sceptre Configuration](sceptre/README.md)
* [Architecture](docs/ARCHITECTURE.md)

### Tools

* [Miscellaneous Tools](tools/README.md)
