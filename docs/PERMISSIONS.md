# Triage Module Permissions

We currently will check JOMAX AD groups.  In the future GoDaddy will use a new RBAC system.  To allow a smooth transition, we will create a utility function to check a user's groups, making a functionality change easy to perform in a single place.

## Temporary documented permissions

This list is a plan on what permissions to give to what module.  In the future, this will likely be dynamically generated from the code / parameters.

* splunk
  * CVE - All infosec
  * Failed ssh logins (IPs) - All infosec
  * Failed okta logins (IPs) - All infosec
  * General logs (any mention of any IOC) - All infosec
* geoip
  * All infosec
  * Any GoDaddy employee TBD
* whois
  * Any GoDaddy employee
* SNOW
  * Any IOC -> searches SNOW (physical_security, incidents) - IR, Treat
  * Godaddy hostname -> CMDB - Infosec
* Tanium (WIP)
  * Hostname -> installed software - Any GoDaddy employee
  * CVE -> All machines with vulnerable software related to the CVE - Only infosec (to start)
* Recorded Future
  * Given CVE -> RF Report - All infosec
* CIRCL
  * Given CVE, CWE, CAPEC, CPE -> Get CIRCL Report -> All GoDaddy
* auth0
  * Given Email -> email, domain, IP blacklist check, is it a free email?, etc - Threat, Employee security, IR
  * Given IP -> blacklist check, score - All infosec
* CMAP
  * Given a domain -> All customer information - NOBODY
  * Given a list of domains -> Metadata (# of domains owned by same person, # of GoDaddy owned domains) - Customer security or subset
* URLhaus
  * Given a domain, URL, IP, hash -> Get if any malware was reported hosted - All GoDaddy
* Email reputation
  * Given email, get email "reputation" from emailrep.io - Threat, Employee security, IR
* Email validation
  * Given email, is it valid (SMTP check) - Threat, Employee security, IR, ?Fraud?
* Haveibeenpwned
  * Given email -> Returned # of breaches, and breach information - All GoDaddy employee
  * Given SHA1 password hash -> How many breaches it appeared in - All GoDaddy employee
* Malware Bazaar
  * Given hash -> Find malware entries from malware bazaar - All GoDaddy
* Threat hunting
  * Given a binary hash -> Returns what machines have run the hash (and if it's a customer machine) -> All infosec
* MITRE
  * Given MITR Tactic, Technique, SubTechnique, MitigationType -> Get MITRE Report - All GoDaddy
* Shodan
  * Given IP, Domain -> Get Shodan report - All infosec
* URLScan
  * Given URL -> Get URLScan report (screenshot, etc) - All GoDaddy

### Other functionality

* Submitting malware to detonate (Cuckoo)
  * All infosec
* Search / Download our malware catalog
  * Search -> All GoDaddy
  * Download -> Threat, IR
* Smaller stuff (Anomali, VT)

### Automation

* HashDB (comparing bad hashes with hashes running on GoDaddy machines)
* Malware classification / clustering
  * All GoDaddy
* EagleEye
  * Listens for HIBP Breaches, Pastebin, enrich, then re-alert (SNOW)
  