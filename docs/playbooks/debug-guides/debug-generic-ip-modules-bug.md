# Generic error for IPs

On June 23rd 2022, there was an error report in #threat-response channel while attempting to triage 21 IP addresses. The exact IP addresses have been redacted in this write up, but the debugging process is explained in detail.

## Exact error reported
"So just put a bunch of IPs into threatui -- got some weird results. I submitted 21 total IPs. for api void it only looked up 5 of them? for passive total it only looked up 5 of them? shodan looked up 9 of them? but to further confuse things the metadata for shodan says 6/21 have vulnerabilities associated. so should i have expected 21 results, or 6? for virus total the response doesnt' tell me what IP the data is for... so i have 21 objects that are numerically numbered, but the data doesn't contain the IP itself so i have no clue what data returned goes with what IP...."


### How debugging went

- Replicate the bug with IoCs and modules
- In this specific error there were 21 IPs and 6 modules involved

Putting them visually,


| IPs         | apivoid     | passivetotal      | recordedfuture    | shodan        | trustar |    virustotal   |
| ----------- | ----------- | -----------       | -----------       | -----------   | ----------- | ----------- |
| IP1         |             |                   |                   |  Yes          |        |       |
| IP2         |             |                   |                   |  Yes          |        |       |
| IP3         |             |                   |                   |               |        |       |
| IP4         |             |                   |   Results         |               |        |       |
| IP5         |             | Yes (no results)  |                   |  Yes          |        |       |
| IP6         |             |                   |                   |               |        |       |
| IP7         |             |                   |                   |  Yes          |        |       |
| IP8         | Yes         |                   |                   |               |        |       |
| IP9         | Yes         | Yes (no results)  |                   |               |        |       |
| IP10        |             | Yes (no results)  |                   |  Yes          |        |       |
| IP11        |             |                   |                   |               |        |       |
| IP12        |             |                   |                   |               |        |       |
| IP13        |             |                   |                   |  Yes          |        |       |
| IP14        | Yes         |                   |   Results         |               |        |       |
| IP15        | Yes         |                   |                   |               |        |       |
| IP16        |             |                   |                   |               |        |       |
| IP17        |             | Yes (no results)  |                   |               |        |       |
| IP18        |             | Yes (no results)  |                   |   Yes         |        |       |
| IP19        |             |                   |  Results          |   Yes         |        |       |
| IP20        |             |                   |                   |               |        |       |
| IP21        | Yes         |                   |                   |   Yes         |        |       |


Findings from above:
- For apivoid & Recorded Future:
  - Could be because of some thread handling issues (maxthread is set to 5)
  - Gave random IPs (a mix of what gave answer previously vs no results), it picked up just 5 IPs on UI
  - Backend submits and retrieves all IP results
  - [UI bug work in progress]

- Other minor UI/UX fixes were created as stories for future work
  - More readability on which result is for which IoC
  - Removing "no returned result" from display
