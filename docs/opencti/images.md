# OpenCTI Container Images

OpenCTI is intended to be deployed using the Docker containerization service. By default, the Luatix-provided Docker files utilize public images. The Threat Research team adapted these files to use the corresponding Golden Container Image (GCI) versions.

| Component | GitHub | Image | GHEC | GCI |
|-----------|--------|-------|------|-----|
| Platform  | [https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/Dockerfile](https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/Dockerfile) | node:16-alpine | [https://github.com/gdcorp-infosec/threat-ioc-store/blob/develop/containers/worker/Makefile](https://github.com/gdcorp-infosec/threat-ioc-store/blob/develop/containers/worker/Makefile) | alpine-node:16.15.0-alpine-3.14 |
| Worker    | [https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-worker/Dockerfile](https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-worker/Dockerfile) | python:3.9.12-alpine3.15 | [https://github.com/gdcorp-infosec/threat-ioc-store/blob/develop/containers/worker/Makefile](https://github.com/gdcorp-infosec/threat-ioc-store/blob/develop/containers/worker/Makefile) | alpine-python3:3.9.12-alpine-3.15 |
| Connector | [https://github.com/OpenCTI-Platform/connectors](https://github.com/OpenCTI-Platform/connectors) | python:3.9-alpine | [https://github.com/gdcorp-infosec/threat-ioc-store/blob/develop/containers/cve/Makefile](https://github.com/gdcorp-infosec/threat-ioc-store/blob/develop/containers/cve/Makefile) | alpine-python3:3.9-alpine-3.14 |


These images are stored in ECR at `764525110978.dkr.ecr.us-west-2.amazonaws.com`.