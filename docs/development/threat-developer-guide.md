# ThreatTools API Development

### AWS Accounts

All AWS accounts are in the us-west-2 (Oregon) region.

| AWS Account | API Endpoint | Environment | Description
| --- | --- | --- | ---
| 345790377847 | https://api-private.threat.int.dev-gdcorp.tools | dev-private | Account for active development (non-CICD)
| 786677461057 | https://api.threat.int.dev-gdcorp.tools | dev | Account for active development (CICD)
| 338932590174 | https://api.threat.int.gdcorp.tools | prod | Production account (CICD)

### Authentication

* All endpoints behind the API gateway require a valid JWT

* [THREAT-487](https://jira.godaddy.com/browse/THREAT-487) replaces the default
  JWTAuthorizer and enforces a [medium impact (non
  delegation)](https://confluence.godaddy.com/display/AUTH/Security+Tokens)
  token strength

* [THREAT-486](https://jira.godaddy.com/browse/THREAT-486) provides a library
  which individual APIs can use to verify JWT age

### JWTs

To obtain a JWT, you can use the [jwt.py](../../tools/jwt.py) script.  The script
will prompt for a username and password, and then print out the JWT.

You may then pass this JWT to the ThreatTools API by setting the
`Authorization` header, using browser tools such as
[ModHeader](https://bewisse.com/modheader/).  The value of the header field
should be `sso-jwt` followed by the JWT, separated by a space character.

### Authorization

Authorization actions and required AD groups can be defined in the metadata for each lambda using the following format:

```json
actions: {
  "viewUsers": {
    "RequiredADGroups": ["ThreatIntel", ...]
  }
}
```

You can then use the _lambda toolbox_ (`lambdas/common/toolbox`) to check authorization in individual lambdas (using a specified list of JOMAX AD groups).  Simply call `Authorize` to see if a particular user can perform an action on a given resource.  Usually (for now) the resource will be the same as the lambda name.

## Writing a lambda

Your lambda can be written in whatever language as long as it follows these input/output guidelines.

### Input

The input to the lambda will be a structure like the following

```json
{
  "jobId": "string", // Job id you are processing
  "submission": events.APIGatewayProxyRequest // The original API Gateway request for the job.
}
```

A few notes about the original request (`submission`):

* The body of the original API request will be in submission.body as a string
  * For the schema of a requested job, reference the [API Usage](IOC.md#Requests) docs.
* The JWT will either be passed in via a cookie or authorization header.  This means you must not log out the full `submission` as it will contain the sensitive and private JWT.  You can use the `toolbox` library to pull out the JWT if you are writing your lambda in go.  You can then call the standard function `Authorize` (in the go toolbox or language equivalent) to check for permissions.

### Output

The output you must return after completing your lambda will be the following.
This is denoted as a `CompletedJob`.  Note that you pass an array of completed jobs because
each lambda can technically accept and array of jobs to handle.
For big output response there is helper method `common.PutObjectInS3`,
which takes big object and saves it in S3 bucket
 `gd-$AWS_DEV_TEAM-$AWS_DEV_ENV-threat-api-job-bucket/responses/$Year/$Month/$Day/$Time_$filename`
 and returns back pre-signed URL valid for 7 days to retrieve file by clients. This URL can be added to response as prop

```json
[
  {
  "jobId": "string", // The job ID that this data should be added to
  "module_name": "string", // The name of this module
  "response": "string", // Marshalled response data
  },
  ...
]
```

### Tracing

Tracing helps us understand what's going on inside each lambda.  We use ELK APM as our tracing server.

In order to add tracing to your lambda, start by making sure your lambda creates the toolbox, and closes it after it's done executing.  This creates the default tracer.  It uses ENV vars to point to the right server.

EX:

```go
t := toolbox.GetToolbox()
defer t.Close(ctx)
```

You can make sure you are setting these env vars correctly by viewing another lambda, or the go APM setup instructions in our APM server.  The env vars are

* ELASTIC_APM_SERVICE_NAME
* ELASTIC_APM_SERVER_URL
* ELASTIC_APM_SECRET_TOKEN

To create a trace, follow the below pattern

```go
var span opentracing.Span
span, ctx = opentracing.StartSpanFromContext(ctx, "NameOfYourTrace")
```

Then for any sub spans, you can simply write the same code again using the newly created context.

Note that you must always close your span, so make sure in all logical flows of your code, your spans will always be closed.
