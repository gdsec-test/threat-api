# Repository Organization

This git repository contains resources grouped by the following functions:

## Documentation

  `docs/`

  This directory contains overall development documentation for the Threat API.
  Process-specific documentation is located in
  [Confluence](https://confluence.godaddy.com/pages/viewpage.action?pageId=129315876)
  instead.

## Threat API Implementation

  `apis/`

  This directory contains sub-directories, one per threat module.  The following
  example shows the layout for the `geoip` threat module:


  | File path | Description
  | --- | ---
  | `apis/recordedfuture/` | This sub-directory contains the definition, configuration, and implementation of the `recordedfuture` threat module.
  | `apis/recordedfuture/.gitignore` | The `.gitignore` file should reference any transient build artifacts, such as `function.zip`.
  | `apis/recordedfuture/docs/` | Development documentation related to the `geoip` threat module.  This documentation should include sensitivity, privacy, and security considerations of any data consumed or produced by this API.
  | `apis/recordedfuture/build.sh` | A script that builds the lambda package as `function.zip`.  **NOTE:** this script must run successfully in a Linux environment (for CICD), and may optionally support alternative environments (MacOS or WSL).
  | `apis/recordedfuture/lambda.json` | Parameters that describe the lambda function to be created.
  | `apis/recordedfuture/recordedfutureLibrary` | Library folder if there is no third party library to be used

  The `lambda.json` file contains the following attributes that correspond to
  the [required
  arguments](https://docs.aws.amazon.com/cli/latest/reference/lambda/create-function.html#options)
  used when creating Lambda functions.  For example:

  ```json
  {
  "handler": "recordedfuture",
  "memory-size": "256",
  "runtime": "go1.x",
  "timeout": "300",
  "metadata": {
    "supportedIOCTypes": [
      "GODADDY_USERNAME",
      "IP",
      "CVE",
      "AWSHOSTNAME"
    ],
    "actions": {
      "ReadRf": {
        "requiredADGroups": ["ENG-Threat Research", "ENG-DCU", "infosec_response"]
      }
    }
  }
}
  ```

  Any data contained in the "metadata" attribute will be serialized and
  populated in a SSM parameter store entry as
  `/ThreatTools/Modules/<THREAT_MODULE_NAME>`.

#### MetaData currently used:
 - Supported [IoC Types](IOCTYPES.md)
 - Actions (Restricted permissions on who can view what data)

## Utility lambdas

`lambdas/`

This folder contains the `manager` and `responceprocessor` lambdas used at other parts of architecture.

Also contains the `common` folder that contains utility functions needed to talk to AWS, Elastic and other services used.

## Sceptre

`sceptre`

This file contains all the configuration and template files needed for cloud formation deployments across all environments.
The [README](../sceptre/README.md) has more details on the step up and other information needed

## Developer tools

`tools/`

This folder contains the tools to make a developer's life easier. For more info and what each script does, please
go through the [README](../tools/README.md) in the folder


## Swagger Spec

  `sceptre/resources/swagger.json`

  This file contains the Swagger specification that's used by Swagger UI
  (Swagger 2.0 format).

## OpenAPI Spec (API Gateway)

  `sceptre/resources/api-setup.json`

  This file contains the OpenAPI specification that's used by the API Gateway
  Service Catalog product.  It contains a superset of the data in the
  `swagger.json` file above, with additional information specifying which
  lambda functions are integrated with the various endpoints.

## GitHub Actions Scripts (CI/CD)

  `.github/`

  See [CICD using Github Actions](CICD.md) for more information.
