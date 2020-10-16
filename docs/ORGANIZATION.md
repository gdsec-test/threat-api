# Repository Organization

This git repository contains resources grouped by the following functions:

* Documentation

  `docs/`

  This directory contains overall development documentation for the Threat API.
  Process-specific documentation is located in
  [Confluence](https://confluence.godaddy.com/pages/viewpage.action?pageId=129315876)
  instead.

* Threat API Implementation

  `apis/`

  This directory contains sub-directories, one per service.  The following
  example shows the layout for the `geoip` service:


  | File path | Description
  | --- | ---
  | `apis/geoip/` | This sub-directory contains the definition, configuration, and implementation of the `geoip` service.
  | `apis/geoip/.gitignore` | The `.gitignore` file should reference any transient build artifacts, such as `function.zip`.
  | `apis/geoip/docs/` | Development documentation related to the `geoip` service.  This documentation should include sensitivity, privacy, and security considerations of any data consumed or produced by this API.
  | `apis/geoip/swagger.json` | The Swagger specification for this specific API (Swagger 2.0 format)
  | `apis/geoip/build.sh` | A script that builds the lambda package as `function.zip`.  **NOTE:** this script must run successfully in a Linux environment (for CICD), and may optionally support alternative environments (MacOS or WSL).
  | `apis/geoip/lambda.json` | Parameters that describe the lambda function to be created.

  The `lambda.json` file contains the following attributes that correspond to
  the [required
  arguments](https://docs.aws.amazon.com/cli/latest/reference/lambda/create-function.html#options)
  used when creating Lambda functions.  For example:

  ```json
  {
    "runtime": "go1.x",
    "timeout": "15",
    "memory-size": "256",
    "handler": "main"
  }
  ```

* Swagger Spec

  `swagger.json`

  This file contains the Swagger specification that's used by Swagger UI
  (Swagger 2.0 format).

  **NOTE:** this file is originally created and maintained as a static file,
  but will be replaced by a process that generates it automatically by
  combining the Swagger information contained within each API.

* OpenAPI Spec (API Gateway)

  `api.json`

  This file contains the OpenAPI specification that's used by the API Gateway
  Service Catalog product.  It contains a superset of the data in the
  `swagger.json` file above, with additional information specifying which
  lambda functions are integrated with the various endpoints.

  **NOTE:** this file is originally created and maintained as a static file,
  but will be replaced by a process that generates it automatically by
  combining the Swagger information contained within each API.

* CI/CD Scripts

  `cicd/` (TBD)

  TBD

