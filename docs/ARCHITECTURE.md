# Threat API Architecture

## High level architecture

![architecture](./diagrams/lambda_architecture.svg)

## Lambda Flow

This sequence diagram describes the execution of spawning a new job.

![Async lambda flow](./diagrams/Asynchronous.svg)

Then to check on the status of a job:

![Poll job](./diagrams/Polling.svg)
