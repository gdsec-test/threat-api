# Threat API

## High Level Architecture

![Threat API](./diagrams/threat_api_aws.svg)

* A custom authorizer verifies that all API Gateway requests have a valid JWT

* Incoming job requests are assigned a unique `job_id` (UUID), and are
  published to the `JobRequests` SNS topic

* Individual service lambdas are subscribed to the SNS topic, and are invoked
  whenever a message containing a request is published

* Each service lambda decides if it should contribute to the results of a
  requested job by examining a `modules` attribute in the original request

* Each service lambda sends its output to the `JobResponses` SQS queue

* The `ResponseProcessor` lambda is triggered by SQS queue submissions, and
  stores the provided output in DynamoDB

* Jobs may be queried by calling the API Gateway and specifying the `job_id`;
  available output from the various service lambdas will be returned to the
  caller

## Job Request Flow

![Job Request Flow](diagrams/job_request_flow.svg)
