# URLhaus Threat Module

The URLhaus threat module takes as input one or more autonomous system numbers (ASNs). These ASNs should be for GoDaddy and its subsidiaries. The module queries URLhaus for these ASNs, parses the returned CSVs, and returns a list of entries for domains that are listed as being "online."

URLhaus requests that users do not abuse the service and avoid querying the API more than once every 10 minutes.