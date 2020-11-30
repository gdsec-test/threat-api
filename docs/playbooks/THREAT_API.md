# Threat API

Threat API is deployed and managed on AWS.  You can see the full architecture on the [architecture diagram](../ARCHITECTURE.md).

This document will be more and more populated as we encounter and document common problems.

## General

For most app level errors and problems, check the [ELK Stack APM Server](https://threattools-non-prod.kibana.int.gdcorp.tools/app/home) (you may need to sign in via okta).  It will most likely have errors that would provide the best trail to follow.

## Permissions error

Check the permissions of the API Gateway...TODO

## 500 Error for a module

Check APM as specified in [#General](#General).

## Gateway is not calling a lambda

Check the connection and permissions from the gateway to the lambda...TODO.
