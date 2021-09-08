### RecordedFuture API
- Latest version of Recorded Future's Connect API is available [here](https://api.recordedfuture.com/v2/#/)
- Alternatively, you can also use `cURL`, other tools like `Postman` or write clients in your fav language!

Example :
- API call for a hash value with API Token and required fields needed to make the call
```sh
curl -H "X-RFToken: [API token]" "https://api.recordedfuture.com/v2/hash/AddHashHere?fields=analystNotes%2Ccounts%2CenterpriseLists%2Centity%2CfileHashes%2ChashAlgorithm%2CintelCard%2Clinks%2Cmetrics%2CrelatedEntities%2Crisk%2CriskMapping%2Csightings%2CthreatLists%2Ctimestamps&metadata=true"

```
- Refer the above link for supported endpoints
- Key in the API key at the top `API Token` box for authentication
- The API token can be got from `Menu` -> `User Settings` -> `API Access`
- If you don't access to RecordedFuture, the same key can also be obtained from `AWS Secrets Manager`


### General Developer CheatSheet
- For getting the GoLang structure from RAW json, you can use [this online tool](https://mholt.github.io/json-to-go/)
- To view the JSON data in collapsible, you can use [this tool](https://codebeautify.org/jsonviewer)
- Make sure you aren't uploading any sensitive data online, the links are just for developer's reference.
  You are free to use a tool of your choice too! Feel free to add them here!
