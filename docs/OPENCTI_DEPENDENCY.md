# OpenCTI Dependency

The OpenCTI service is tier 4 (lowest) priority for avaiability. Degradation or loss of the service will have no impact on GoDaddy business and only minor impact on the larger Threat Tools system. Impacts would be loss of data that would be copied from third-party API responses into OpenCTI for long-term storage.

Our OpenCTI instance has only a few dependencies.
- Okta for SSO to enable interactive user logins.
- Servicenow's Incident Response module stores indicators added by Incident Response analysts during their investigations. These indicators will be backfilled into OpenCTI to cross-reference with data acquired from other sources.

```mermaid
classDiagram
  class OpenCTI {
  	Tier: TIER_4
  	Hosted: PUBLIC_CLOUD
  }

  class SSO {
  	Tier: TIER_0
  	Hosted: PUBLIC_CLOUD
  }

  class ServiceNow {
  	Tier: TIER_0
  	Hosted: ON_PREMISE
  }

  SSO <-- |Verify JWT<br/>Type: SYNC<br/>Routing: SERVER_TO_SERVER<br/>Resiliency: DEGRADE_TO_CACHE&gt;FAIL<br/>RPS: &lt;1K<br/>Burst: 5x<br/>Consumers/Day: Tens<br/>TLS: YES<br/>Authentication: JWT_USER<br/>Authorization: ROUTING| OpenCTI
  SSO --> |Load Credentials<br/>Type: SYNC<br/>Routing: SERVER_TO_SERVER<br/>Resiliency: DEGRADE_TO_CACHE&gt;FAIL<br/>RPS: &lt;1K<br/>Burst: 10x<br/>Consumers/Day: Tens<br/>TLS: YES<br/>Authentication: JWT_USER<br/>Authorization: ROUTING| OpenCTI

  ServiceNow -.-> |Backfill IoCs<br/>Type: ASYNC<br/>Routing: SERVER_TO_SERVER<br/>Resiliency: FAIL<br/>RPS: &lt;1K<br/>Burst: 1x<br/>Consumers/Day: One<br/>TLS: YES<br/>Authentication: JWT_USER<br/>Authorization: ROUTING| OpenCTI
```