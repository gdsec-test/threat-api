# Threat API

Threat API is deployed and managed on AWS.  You can see the full architecture on the [architecture diagram](../ARCHITECTURE.md).

This document will be more and more populated as we encounter and document common problems.

## General

For most app level errors and problems, check the [ELK Stack APM Server](https://threattools-non-prod.kibana.int.gdcorp.tools/app/apm) (sign in via okta).  It will most likely have errors that would provide the best trail to follow.

<details>
<summary>APM Instructions</summary>

Log in to the kibana instance from okta

![okta](./img/elk/okta.png)

Find the APM selection in the sidebar

![apm](./img/elk/apm.png)

From there you can click in to an individual service and view traces (example TODO).

</details>

## Deployment and development

For information on deployment and development see [DEVELOPMENT.md](../DEVELOPMENT.md)

## Permissions error

Check the permissions of the API Gateway...TODO

## Gateway is not calling a lambda

Check the connection and permissions from the gateway to the lambda...TODO.
