# urlscan.io

- This module submits URLs to urlscan.io and returns scan results (final verdicts, screenshot URL, effective redirect URL and final report URL)

## urlscan.io APIs

- API usage documentation is available [here](https://urlscan.io/docs/api/). API Key can be obtained after user registration or login as an existing user. An expired API key should be updated in AWS Secrets manager
- This module uses the Submission API to submit a URL to urlscan.io and the Result API to then fetch URL scan results
- This module leverages the free tier of urlscan.io. The Submission API is rate-limited to 5000 public scans per day, 500 per hour and 60 per minute. The Result API is rate-limited to 120 requests per minute, 5000 per hour and 10000 per day
- Request processing time is 10-20 seconds approximately
- Supported IoCs for this module: URL

## Known Issue

- Submission API's JSON response is syntatically incorrect so https://mholt.github.io/json-to-go/ will not be able to convert it to a syntatically correct Go struct. The response contains approximately 6000 lines of key-value pairs and contains duplicate "request" keys within the same JSON block in "data" (illegal JSON format, keys must be unique within the same block). Values from the data block are currently not required

## Built With

- Golang v1.17.2

## General Developer CheatSheet

- For getting the GoLang structure from RAW json, you can use [this online tool](https://mholt.github.io/json-to-go/)
- To view the JSON data in collapsible format, you can use [this tool](https://codebeautify.org/jsonviewer)
- Useful article on handling schemaless dynamic JSON responses in Golang (required when JSON response from an API is syntatically illegal) [GoLang : Dynamic JSON Parsing using empty Interface and without Struct in Go Language] (https://irshadhasmat.medium.com/golang-simple-json-parsing-using-empty-interface-and-without-struct-in-go-language-e56d0e69968)
- Make sure you aren't uploading any sensitive data online, the links are just for developer's reference.
  You are free to use a tool of your choice too! Feel free to add them here!