package main

var TestRecordedFutureIPReportData = `{
				"data": {
						"riskyCIDRIPs": [
								{
										"score": 29,
										"ip": {
												"id": "ip:123.45.67.89",
												"name": "123.45.67.89",
												"type": "IpAddress"
										}
								},
								{
										"score": 28,
										"ip": {
												"id": "ip:23.45.67.9",
												"name": "23.45.67.9",
												"type": "IpAddress"
										}
								}
						],
						"enterpriseLists": [],
						"risk": {
								"criticalityLabel": "Unusual",
								"riskString": "3/64",
								"rules": 3,
								"criticality": 1,
								"riskSummary": "3 of 64 Risk Rules currently observed.",
								"score": 15,
								"evidenceDetails": [
										{
												"mitigationString": "",
												"evidenceString": "1 sighting on 1 source: External Sensor Spam. was historically observed as spam. No longer observed as of Nov 16, 2021.",
												"rule": "Historical Spam Source",
												"criticality": 1,
												"timestamp": "2021-11-16T04:23:06.028Z",
												"criticalityLabel": "Unusual"
										}
								]
						},
						"intelCard": "https://app.recordedfuture.com/live/sc/entity/ip%3A216.151.180.100",
						"sightings": [
								{
										"source": "GitHub",
										"url": "https://github.com/",
										"published": "2017-04-13T07:54:49.275Z",
										"fragment": "123.45.67.89",
										"title": "blocklist_de_bots.ipset",
										"type": "first"
								},
								{
										"source": "check-my-ip.net",
										"url": "https://www.check-my-ip.net/all-ip-addresses/123.45.67.89",
										"published": "2017-06-13T01:10:15.003Z",
										"fragment": "123.45.67.89 | 123.45.67.9",
										"title": "123.45.67.89 All IP Addresses - Check My IP",
										"type": "mostRecent"
								}
						],
						"entity": {
								"id": "ip:123.45.67.89",
								"name": "123.45.67.89",
								"type": "IpAddress"
						},
						"relatedEntities": [
								{
										"entities": [
												{
														"count": -1,
														"entity": {
																"id": "ip:123.45.67.91",
																"name": "123.45.67.91",
																"type": "IpAddress"
														}
												}
										],
										"type": "RelatedIpAddress"
								}
						],
						"analystNotes": [],
						"location": {
								"organization": "StackPath LLC",
								"cidr": {
										"id": "ip:123.45.67.0/24",
										"name": "123.45.67.0/24",
										"type": "IpAddress"
								},
								"location": {
										"continent": null,
										"country": null,
										"city": null
								},
								"asn": "AS12345"
						},
						"timestamps": {
								"lastSeen": "2017-06-13T01:10:15.003Z",
								"firstSeen": "2017-04-13T07:54:49.283Z"
						},
						"threatLists": [],
						"counts": [
								{
										"date": "2017-04-15",
										"count": 5
								}
						],
						"metrics": [
								{
										"type": "totalHits",
										"value": 19
								},
								{
										"type": "predictionModelVerdict",
										"value": 1
								},
								{
										"type": "c2Subscore",
										"value": 0
								},
								{
										"type": "phishingSubscore",
										"value": 0
								},
								{
										"type": "spamSightings",
										"value": 1
								},
								{
										"type": "spam",
										"value": 1
								},
								{
										"type": "sixtyDaysHits",
										"value": 0
								},
								{
										"type": "sevenDaysHits",
										"value": 0
								},
								{
										"type": "whitlistedCount",
										"value": 0
								},
								{
										"type": "oneDayHits",
										"value": 0
								},
								{
										"type": "trendVolume",
										"value": 0
								},
								{
										"type": "historicalThreatListMembershipSightings",
										"value": -1
								},
								{
										"type": "socialMediaHits",
										"value": 0
								},
								{
										"type": "undergroundForumHits",
										"value": 0
								},
								{
										"type": "infoSecHits",
										"value": 19
								},
								{
										"type": "historicalThreatListMembership",
										"value": 1
								},
								{
										"type": "maliciousHits",
										"value": 0
								},
								{
										"type": "darkWebHits",
										"value": 0
								},
								{
										"type": "publicSubscore",
										"value": 15
								},
								{
										"type": "pasteHits",
										"value": 0
								},
								{
										"type": "mitigatedCount",
										"value": 0
								},
								{
										"type": "criticality",
										"value": 1
								},
								{
										"type": "technicalReportingHits",
										"value": 0
								}
						]
				}
			}`

var TestRecordedFutureHASHReportData = `{
				"data": {
						"enterpriseLists": [],
						"sightings": [
								{
										"source": "PolySwarm",
										"url": "https://polyswarm.network/scan/results/file/12345",
										"published": "2021-02-17T18:50:10.698Z",
										"fragment": "Outbreak 12345 Trojan:Android/BoxerSms 12345",
										"title": "PolySwarm report for 12345",
										"type": "mostRecent"
								}
						],
						"riskMapping": [
								{
										"rule": "Linked to Malware",
										"categories": [
												{
														"framework": "MITRE",
														"name": "TA0002"
												}
										]
								}
						],
						"entity": {
								"id": "hash:1234567890",
								"name": "1234567890",
								"type": "Hash"
						},
						"relatedEntities": [
								{
										"entities": [
												{
														"count": 22,
														"entity": {
																"id": "1234",
																"name": "Trojan",
																"type": "MalwareCategory"
														}
												}
										],
										"type": "RelatedMalwareCategory"
								},
								{
										"entities": [
												{
														"count": 1,
														"entity": {
																"id": "hash:12345",
																"name": "12345",
																"type": "Hash"
														}
												}
										],
										"type": "FileHashes"
								}
						],
						"analystNotes": [],
						"hashAlgorithm": "MD5",
						"timestamps": {
								"lastSeen": "2022-01-25T07:00:04.129Z",
								"firstSeen": "2019-04-28T06:42:19.004Z"
						},
						"threatLists": [],
						"risk": {
								"criticalityLabel": "Malicious",
								"riskString": "2/14",
								"rules": 2,
								"criticality": 3,
								"riskSummary": "2 of 14 Risk Rules currently observed.",
								"score": 70,
								"evidenceDetails": [
										{
												"mitigationString": "",
												"evidenceString": "8 sightings on 1 source: PolySwarm",
												"rule": "Linked to Malware",
												"criticality": 2,
												"timestamp": "2021-02-17T18:50:10.698Z",
												"criticalityLabel": "Suspicious"
										}
								]
						},
						"fileHashes": [
								"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
								"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
								"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"								
						],
						"intelCard": "https://app.recordedfuture.com/live/sc/entity/hash%12345",
						"links": {
								"error": "High Confidence Links information is only available to Recorded Future"
						},
						"counts": [
								{
										"date": "2018-12-25",
										"count": 1
								}
						],
						"metrics": [
								{
										"type": "sevenDaysHits",
										"value": 0
								},
								{
										"type": "oneDayHits",
										"value": 0
								},
								{
										"type": "totalHits",
										"value": 93
								},
								{
										"type": "linkedToMalware",
										"value": 1
								},
								{
										"type": "positiveMalwareVerdictSightings",
										"value": 2
								},
								{
										"type": "whitelistedCount",
										"value": 0
								},
								{
										"type": "positiveMalwareVerdict",
										"value": 2
								},
								{
										"type": "socialMediaHits",
										"value": 0
								},
								{
										"type": "undergroundForumHits",
										"value": 0
								},
								{
										"type": "infoSecHits",
										"value": 79
								},
								{
										"type": "linkedToMalwareSightings",
										"value": 8
								},
								{
										"type": "maliciousHits",
										"value": 4
								},
								{
										"type": "darkWebHits",
										"value": 0
								},
								{
										"type": "publicSubscore",
										"value": 70
								},
								{
										"type": "pasteHits",
										"value": 0
								},
								{
										"type": "mitigatedCount",
										"value": 0
								},
								{
										"type": "criticality",
										"value": 3
								},
								{
										"type": "technicalReportingHits",
										"value": 93
								},
								{
										"type": "malwareSubscore",
										"value": 70
								},
								{
										"type": "sixtyDaysHits",
										"value": 0
								}
						]
				}
			}`

var TestRecordedFutureCVEReportData = `{
				"data": {
						"relatedLinks": [
								"http://www.ubuntu.com/usn/USN-5346-1",
								"http://www.securityfocus.com/bid/66690"
						],
						"analystNotes": [
								{
										"attributes": {
												"validated_on": "2022-01-27T20:15:36.015Z",
												"published": "2022-01-27T20:31:08.949Z",
												"text": "On January 26, 2022, Federal Bureau of Investigation (FBI) ",
												"topic": {
														"id": "aDKkpk",
														"name": "TTP Instance",
														"type": "Topic",
														"description": "Notes on tools, scripts, or malware sourced from Recorded Future proprietary sources that may be used in future adversarial campaigns."
												},
												"context_entities": [
														{
																"id": "ZaEWgI",
																"name": "CVE-2019-9621",
																"type": "CyberVulnerability",
																"description": "Zimbra Collaboration Suite before 8.6 patch"
														},
														{
																"id": "Slrqtd",
																"name": "CVE-2017-5930",
																"type": "CyberVulnerability",
																"description": "The AliasHandler component in PostfixAdmin "
														}
												],
												"validation_urls": [
														{
																"id": "url:url:https://www.ic3.gov/Media/News/2022/12345.pdf",
																"name": "url:https://www.ic3.gov/Media/News/2022/12345.pdf",
																"type": "URL"
														},
														{
																"id": "url:url:https://app.recordedfuture.com/live/sc/12345",
																"name": "url:https://app.recordedfuture.com/live/sc/12345",
																"type": "URL"
														}
												],
												"title": "FBI Disclosed TTP Overview on ",
												"note_entities": [
														{
																"id": "gXHjim",
																"name": "Net Pas",
																"type": "Company"
														}
												]
										},
										"source": {
												"id": "VKz42X",
												"name": "Group",
												"type": "Source"
										},
										"id": "lcHe_f"
								}
						],
						"enterpriseLists": [],
						"risk": {
								"criticalityLabel": "Critical",
								"riskString": "16/21",
								"rules": 16,
								"criticality": 4,
								"riskSummary": "16 of 21 Risk Rules currently observed.",
								"score": 89,
								"evidenceDetails": [
										{
												"mitigationString": "",
												"evidenceString": "67 sightings on 20 sources including",
												"rule": "Historically Linked to Remote Access Trojan",
												"criticality": 1,
												"timestamp": "2019-12-15T02:13:07.000Z",
												"criticalityLabel": "Low"
										}
								]
						},
						"commonNames": [
								"Heartbleed"
						],
						"cvssv3": {
								"scope": "UNCHANGED",
								"exploitabilityScore": 3.9,
								"modified": "2020-10-15T13:29:00.000Z",
								"baseSeverity": "HIGH",
								"baseScore": 7.5,
								"privilegesRequired": "NONE",
								"userInteraction": "NONE",
								"impactScore": 3.6,
								"attackVector": "NETWORK",
								"integrityImpact": "NONE",
								"confidentialityImpact": "HIGH",
								"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
								"version": "3.1",
								"attackComplexity": "LOW",
								"created": "2014-04-07T22:55:00.000Z",
								"availabilityImpact": "NONE"
						},
						"cpe22uri": [
								"cpe:/a:openssl:openssl:1.0.1:beta1",
								"cpe:/o:redhat:enterprise_linux_server_aus:6.5"
						],
						"sightings": [
								{
										"source": "SYS-CON Media",
										"url": "http://www.sys-con.com/node/2863732",
										"published": "2013-11-05T15:11:38.000Z",
										"fragment": "Additional commentary on today's news is available on F5 DevCentral ™ at: https://devcentral.f5.com/articles/f5-synthesis-the-time-is-right.",
										"title": "F5 Introduces Synthesis Architecture for Software Defined Application Services (SDAS)",
										"type": "first"
								}
						],
						"entity": {
								"id": "K5GW38",
								"name": "CVE-2014-0160",
								"type": "CyberVulnerability",
								"description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug."
						},
						"cpe": [
								"cpe:2.3:a:openssl:openssl:1.0.1d:*:*:*:*:*:*:*",
								"cpe:2.3:a:openssl:openssl:1.0.1:beta2:*:*:*:*:*:*"
						],
						"timestamps": {
								"lastSeen": "2022-02-03T00:16:48.398Z",
								"firstSeen": "2013-11-05T15:11:54.893Z"
						},
						"threatLists": [],
						"intelCard": "https://app.recordedfuture.com/live/sc/entity/K5GW38",
						"rawrisk": [
								{
										"rule": "linkedToRAT",
										"timestamp": "2019-12-15T02:13:07.000Z"
								}
						],
						"counts": [
								{
										"date": "2021-03-26",
										"count": 47
								}
						],
						"metrics": [
								{
										"type": "malwareActivity",
										"value": 1
								}
						],
						"relatedEntities": [
								{
										"entities": [
												{
														"count": 1279,
														"entity": {
																"id": "J0Nl-p",
																"name": "Ransomware",
																"type": "MalwareCategory"
														}
												}
										],
										"type": "RelatedMalwareCategory"
								},
								{
										"entities": [
												{
														"count": 13559,
														"entity": {
																"id": "LHAvVM",
																"name": "CVE-2014-0224",
																"type": "CyberVulnerability",
																"description": "OpenSSL before 0.9.8za"
														}
												}
										],
										"type": "RelatedCyberVulnerability"
								}
						],
						"nvdDescription": "The (1) TLS and (2) DTLS implementations ",
						"cvss": {
								"accessVector": "NETWORK",
								"lastModified": "2020-10-15T13:29:00.000Z",
								"published": "2014-04-07T22:55:00.000Z",
								"score": 5,
								"availability": "NONE",
								"authentication": "NONE",
								"accessComplexity": "LOW",
								"integrity": "NONE",
								"confidentiality": "PARTIAL",
								"version": "2.0"
						}
				}
			}`
