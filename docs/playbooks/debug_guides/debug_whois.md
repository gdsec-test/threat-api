# Debugging the WHOIS Module

The whois module is broken. To trace through the issue, we must follow the following steps:
1. View/recreate the bug
2. View in AWS logs/Identify Potential Lamba Issues
3. Use Splunk Queries for Additional Insight
4. Explore Potential Solutions
5. Make Necessary Changes (Code or AWS Environment)


## View Bug

In our whois local module, if we run the "go test" command, we get the following output:

```
[{"Title":"Whois lookup data","Metadata":[],"DataType":""
"Data":"domain,createdDate,updatedDate,expirationDate,registrarName,registrarEmail
registrarPhone,registrantName,registrantEmail,registrantPhone,registrantOrganization
registrantStreet,

registrantCity,registrantCountry,administrativeOrganization\ngodaddy.com
1999-03-02T05:00:00Z,2020-04-07T14:26:27Z,2021-11-01T11:59:59Z,\"GoDaddy.com, LLC\"
abuse@godaddy.com,+1.4806242505,,select contact domain holder link at https://www
godaddy.com/whois/results.aspx?domain=godaddy.com,,\"Go Daddy Operating Company, LLC\"
,,US,\n"}]

PASS

ok
```

This indicates that the whois server can be reached locally. However, the dev-private
swagger displays the following error:

```
  "responses": {
    "whois": [
      {
        "Data": "domain,createdDate,updatedDate,expirationDate,registrarName,
        registrarEmail,registrarPhone,registrantName,registrantEmail,registrantPhone,
registrantOrganization,registrantStreet,registrantCity,registrantCountry,
administrativeOrganization\ngodaddy.com,,,,ERROR: whois: query for whois server failed:
whois: connect to whois server failed: dial tcp 192.0.32.59:43: i/o timeout,,,,,,,,,,
\n",
        "DataType": "",
        "Metadata": [
          "1/1 Domains are invalid (bad whois data)"
        ],
        "Title": "Whois lookup data"
      }
    ]
  },
```

## View in AWS/Identify Potential Lambda issues

To look at detailed aws logs, we need to use the Threat Tools Dev Private Power User
Account, and specifically visit Cloudwatch > Log Groups > search for "whois"  > choose
"/aws/lambda/whois".

Assuming our test was the latest, choose the top result. Through inspecting the logs
we can see that this is an issue related to the AWS Lamba:
[[https://github.com/gdcorp-infosec/threat-api/blob/develop/docs/playbooks/
debug_guides/debug_images/whois/logevents.png]]

[[https://github.com/gdcorp-infosec/threat-api/blob/develop/docs/playbooks/
debug_guides/debug_images/whois/error.png]]

To further investigate the issue, we can look at whether or not there is a firewall/
WAF block. In the same account, search for "WAF & Shield" and then "Web ACLs" from the
menu on the left. Ensure you're in the US West (Oregon) region and choose
Threat-Regional-WebACL. Search for "BLOCKED" in the sample requests field at the
bottom. In this case, there were no results yielded so we know it is not a WAF issue:

[[https://github.com/gdcorp-infosec/threat-api/blob/develop/docs/playbooks/
debug_guides/debug_images/whois/blocked.png]]


## Use Splunk Queries for Additional Insight

By looking at the error message in AWS, we can see that there is an issue reaching the
server 192.0.32.59:43. The following splunk lookup can help:

```
index="aws_vpc_flowlogs" product=threattools 192.0.32.59
```

This results in the following logs


[[https://github.com/gdcorp-infosec/threat-api/blob/develop/docs/playbooks/
debug_guides/debug_images/whois/splunklogs_one.png]]

We can see that all the reject messages are coming from the source: 10.119.177.8. Sowe
can use the following Splunk query to further investigate

```
index="aws_vpc_flowlogs" 10.119.177.8
```
[[https://github.com/gdcorp-infosec/threat-api/blob/develop/docs/playbooks/
debug_guides/debug_images/whois/splunklogs_two.png]]

## Potential Solutions

Given all the accepts messages in Splunk, we had several new ideas for possible
solutions:

1. Contact AWS - create a ticket with them to further investigate
2. Scrape WHOIS module completely
3. Assuming the likexian default server is blocking AWS traffic, create a pull request from  github.com/likexian/whois, the github program that
handles our whois queries. Line 35 on their whois.go file in the repo outlines the
default server: defaultWhoisServer = "whois.iana.org"
4. Find a different way to query another server

We thought that solution 4 would be best. In our whois.go file, we found the function
call:

```
whois.Whois(domain)
```

By reading through the likexian
documentation, we understood that this is how the default whois server was queried and
found a way to query a different one. The new call was:

```
whois.Whois("whois.godaddy.com")
```
We tried this with other servers too such as whois.centralnic.com. We realized that
since that did not solve the problem, it was more likely that our AWS setting were
blocking traffic somehow. Revisiting the error message:

```
dial tcp 192.0.32.59:43: i/o timeout,,,,,,,,,,
```
We realized that perhaps the issue is blocking TCP traffic to a specific port. We need
to use the Threat Tools Dev Private Power User Account, and specifically visit
Cloudwatch > Log Groups > search for "whois"  > choose "/aws/lambda/whois".

[[https://github.com/gdcorp-infosec/threat-api/blob/develop/docs/playbooks/
debug_guides/debug_images/whois/outbound_rules.png]]

The "Deny" message in rule 170 of our Outbound Rules shows that rule 170 is blocking
TCP traffic to all ports.

## Make Necessary Changes

We need a custom rule that will allow TCP traffic to port 43.

[[https://github.com/gdcorp-infosec/threat-api/blob/develop/docs/playbooks/
debug_guides/debug_images/whois/customtcp.png]]

Problem Solved! Since these changes were only applied in the DEV-Private Account, we must use an account with elevated access to make the same changes in our DEV and PROD accounts and ensure a smooth CICD process.
