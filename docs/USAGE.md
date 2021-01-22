# Threat API Usage

### IOC Types

The following IOC types are supported:

| IOC Type | Description
| -------- | -----------
| `unknown` | Unknown
| `domain` | Domain
| `email` | Email Address
| `cve` | CVE
| `cwe` | CWE
| `capec` | CAPEC
| `cpe` | CPE
| `url` | URL
| `md5` | MD5 Hash
| `sha1` | SHA1 Hash
| `sha256` | SHA256 Hash
| `sha512` | SHA512 Hash
| `ip` | IP Address
| `hostname` | Hostname (GoDaddy machine hostnames)
| `awshostname` | Hostname (AWS hostnames)
| `godaddy_username` | GoDaddy Username
| `mitre_tactic` | Mitre Tactic
| `mitre_technique` | Mitre Technique
| `mitre_subtechnique` | Mitre Subtechnique
| `mitre_mitigation` | Mitre Mitigation

#### Classifying IOC types

To classify an IOC type you can call the endpoint `/classify` with the following body

```json
{
  "iocs": ["1.1.1.1", "domain.com"] // String list of IOCs
}
```

It will respond with a response similar to the following

```json
{
  "domain": ["domain.com"],
  "ip": ["1.1.1."]
}
```

### Requests

Requests to the Threat API are specified using the following request format:

```json
{
  "ioc_type": "godaddy_username",
  "iocs": [
    "clake1",
    "gbailey",
    "dcomes",
    "jmwhite"
  ],
  "modules": [
    "whois",
  ],
}
```

Each request specifies a single IOC type and includes a list of one or more
IOCs of that type.

A single `job_id` is returned in response to a `POST` request to the `/job`
endpoint.

### Responses

The status and any available output for a given `job_id` can be obtained from
the `/job/{job_id}` endpoint.

The `responses` field of the returned JSON data includes responses from each
service lambda that contributed output for specified IOCs.

Example response when querying a `job_id` of `12345`:

```json
{
  "job_id": "12345",
  "job_status": "Completed",
  "job_percentage": 100.00,
  "responses": {
    "splunk": {
      "output": "Splunk specific results"
    },
    "servicenow": {
      "output": "ServiceNow specific results"
    }
  }
}
```
