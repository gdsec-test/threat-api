# Threat API

Threat API is deployed and managed on AWS.  You can see the full architecture on the [architecture diagram](../ARCHITECTURE.md).

This document will be more and more populated as we encounter and document common problems.

## Business Service and Support Group Information

The Threat API and UI are both supported by the same business service (Threat Tools) and support group (ENG-Threat Research). ENG-Threat Research has an oncall group setup that can be found at https://godaddy.service-now.com/oncall and searching for ENG-Threat Research.

You can edit the Business Service details by going to this link - https://godaddy.service-now.com/nav_to.do?uri=cmdb_ci_service.do?sys_id=947c98561bb52010ddbe21be6e4bcb6a

Our Service is a Tier 3 service and complies with the availability and monitoring standards at - https://github.secureserver.net/CTO/guidelines/blob/master/Standards-Best-Practices/Monitoring/Monitoring%20Standard.md
https://github.secureserver.net/CTO/guidelines/blob/master/Standards-Best-Practices/Monitoring/Availability%20Standard.md

Uptime Requirement - Our service shall comply with the targets assigned in the availability standard for greater than 99.0% uptime. In reality, I expect our service will be greater than 99.5% given we are utilizing serverless and fargate AWS services. Site24x7 will be used to measure uptime availability and will be monitoring both Web UI - https://ui.threat.int.gdcorp.tools/ and REST API - https://api.threat.int.gdcorp.tools/.

## Troubleshooting Overview

Our Architecture is made up of both API and UI components. We will monitor the following aspects of each in compliance with availability and monitoring standards:
* API
  * Dead Letter Queue for Lambda Jobs to monitor end-user experience
  * APM metrics to trace all API requests. Instructions below in this page.
  * API Gateway cloudwatch alarms with Moogsoft integration
  * DynamoDB job results troubleshooting (jobs not listed in DynamoDB)
  * Cloudwatch & Cloudtrail logs for other errors that show up: including Lambda failures - Jira story to complete
* UI
  * Site24x7 for UI health status - https://ui.threat.int.gdcorp.tools/healthcheck - Prod Jira story to complete (https://jira.godaddy.com/browse/PRODUCTSEC-1301)
  * Fargate container failure Cloudwatch alarm with Moogsoft integration - Prod Jira story to complete https://jira.godaddy.com/browse/PRODUCTSEC-1304)
  * ALB cloudwatch alarms with Moogsoft integration - Prod Jira story t complete https://jira.godaddy.com/browse/PRODUCTSEC-1304)
* General Logging
  * Application Logs will be sent to ESSP stack - https://threattools-non-prod.kibana.int.gdcorp.tools/app/home#/
  * Application Security Event Logs will be sent to security logging pipeline per the application logging standard at x.co/appseclog
    * Events going to the application security logging stream will include AuthZ events, and Job submission metadata


## General Troubleshooting

For most app level errors and problems, check the [ELK Stack APM Server](https://threattools-non-prod.kibana.int.gdcorp.tools/app/apm) (sign in via okta).  It will most likely have errors that would provide the best trail to follow.

<details>
<summary>APM Instructions</summary>

Log in to the kibana instance from okta

![okta](./img/elk/okta.png)

Find the APM selection in the sidebar

![apm](./img/elk/apm.png)

From there you can click in to an individual service and view traces (example TODO).

</details>

<details>
<summary>Cloudwatch Logs</summary>
- For specific lambda's errors - check the corresponding log group (`/aws/lambda/lambdaName`) in AWS Cloudwatch
- If the specific lambda doesn't have errors, check log groups of `/aws/lambda/manager` and `/aws/lambda/responseprocessor` for more info

</details>

## Threat UI Tenet Troubleshooting

Please review additional troubleshooting steps at - https://github.com/gdcorp-infosec/threat-ui-tenet/blob/main/TROUBLESHOOT.md

## Gateway is not calling a lambda

Check the connection and permissions from the gateway to the lambda.  This will most likely be sceptre changes.  Check for error codes and dig deeper based on them.

## Lambda is not being run

If you notice that your lambda is not being run, it is most likely a problem with the connection to the SNS topic.
Currently, on every job triggering, each lambda should trigger.
And it's up to the lambda to determine if it should run and generate results.
So if you lambda is not running, it is not listening to the SNS topic properly.

Make sure the lambda is set up to be triggered from the proper SNS topic, and review the sceptre files for this.
![sns JobRequests](../diagrams/sns_lambdas.png)

If your lambda is still not running, check it's execution role, it should use the threat lambda execution role.

## Lambda results are not loading in to DynamoDB

If your lambda is definitely running (it runs and sends logs to cloudwatch), but the results are not populating to DynamoDB, here's what you should do to debug.

The problem is most likely directly between your lambda and Dynamodb.  Check out the [architecture](../ARCHITECTURE.md) docs to see the elements in between.

1. First check to make sure the response processor is picking up on your result.  Your lambda should be sending the results to the SQS queue that then is processed by the response processor.  Check to make sure your lambda has this destination set up as shown below.
![lambda SQS connections](../diagrams/lambda_sqs.png)
1. Next check the logs of the response processor, this is the most likely place of error.  If your results are sent in the wrong format, the response processor will log it. Check input format for response processor [here](../development/threat-developer-guide.md#output)
1. Next check if the result is being populated to DynamoDB.
![dynamoDB_joblists](../diagrams/dynamodb_joblists.png)
If it is, great, it's likely just the manager lambda not properly decrypting and returning the results via the API. If not, it's worth doing deeper debugging in the response processor to check for code bugs or other errors.  See APM Instructions.
1. If you check all these spots, but none show an indication of failure, it's probably worth doing deeper debugging in the code of the [response processor](../../lambdas/responseprocessor), and [manager lambda](../../lambdas/manager), depending on what is not working.

### For specific use case errors refer [debug_guides](debug-guides)
