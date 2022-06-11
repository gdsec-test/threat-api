#### Tanium API token

- Tanium API token is currently generated manually from the tanium UI and copied into AWS secrets manager for authentication.
- Coresponding service account is - `SVCFnoGRa1LtN2o6r`, password can be obtained from either CyberArk or AWS secrets manager.
- API token is restricted to specific IP ranges only. The one in AWS Secrets Manager is confined to work only from Tanium lambda.
  - The current token is set to expire on 7/6/2022, 11:42:02 AM
- To test locally, create a short lived API token adding your local IP address. Go to https://tanium-dev.int.gdcorp.tools/#/console/api-tokens and add your IP address to trusted IPs. (Turn on VPN and use `ifconfig` if you are on Mac, look for POINTOPOINT interface, otherwise VPN IP can be found in GlobalProtect VPN Settings)
