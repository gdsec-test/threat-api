package main

import (
	"encoding/json"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"

	. "github.com/smartystreets/goconvey/convey"
)

func TestDumpCSV(t *testing.T) {

	Convey("dumpCSV", t, func() {
		tb = toolbox.GetToolbox()
		// setup stubs\mocks
		patches := []*Patches{}

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should dump proper CSV output for DOMAIN", func() {
			APIvoidReportData := &APIvoidReport{}

			responseReportString := `{
				"data": {
						"report": {
								"host": "gumblar.cn",
								"blacklists": {
										"engines": [
											{
													"engine": "Phishing Test",
													"detected": false,
													"reference": "https://www.novirusthanks.org/",
													"confidence": "low",
													"elapsed": "0.00"
											},
											{
													"engine": "Scam Test",
													"detected": false,
													"reference": "https://www.novirusthanks.org/",
													"confidence": "low",
													"elapsed": "0.00"
											}
										],
										"detections": 3,
										"engines_count": 47,
										"detection_rate": "6%",
										"scantime": "0.38"
								},
								"server": {
										"ip": "103.224.182.249",
										"reverse_dns": "lb-182-249.above.com",
										"continent_code": "OC",
										"continent_name": "Oceania",
										"country_code": "AU",
										"country_name": "Australia",
										"region_name": "Victoria",
										"city_name": "Beaumaris",
										"latitude": -37.982200622558594,
										"longitude": 145.0389404296875,
										"isp": "Trellian Pty. Limited",
										"asn": "AS133618"
								},
								"category": {
										"is_free_hosting": false,
										"is_anonymizer": false,
										"is_url_shortener": false,
										"is_free_dynamic_dns": false
								},
								"security_checks": {
										"is_most_abused_tld": false,
										"is_domain_blacklisted": true,
										"is_uncommon_host_length": false,
										"is_uncommon_dash_char_count": false,
										"is_uncommon_dot_char_count": false,
										"website_popularity": "low",
										"is_risky_category": false
								},
								"risk_score": {
										"result": 100
								}
						}
				},
				"credits_remained": 96535.6,
				"estimated_queries": "1,206,695",
				"elapsed_time": "0.60",
				"success": true
			}`
			json.Unmarshal([]byte(responseReportString), &APIvoidReportData)

			expectedCSV := "IoC,BL Engine,Blacklisted,Confidence\ngumblar.cn,Phishing Test:https://www.novirusthanks.org/,false,low\ngumblar.cn,Scam Test:https://www.novirusthanks.org/,false,low\n"

			reports := map[string]*APIvoidReport{
				"gumblar.cn": APIvoidReportData,
			}
			actualCSV := dumpCSV(reports, triage.DomainType)
			So(actualCSV, ShouldResemble, expectedCSV)
		})

		Convey("should dump proper CSV output for IP", func() {
			APIvoidReportData := &APIvoidReport{}

			responseReportString := `{
				"data": {
						"report": {
								"ip": "80.82.77.139",
								"blacklists": {
										"engines": [
												{
														"engine": "Barracuda_Reputation_BL",
														"detected": false,
														"reference": "http://www.barracudanetworks.com/",
														"elapsed": "0.03"
												},
												{
														"engine": "BlockedServersRBL",
														"detected": true,
														"reference": "https://www.blockedservers.com/",
														"elapsed": "0.03"
												}
										],
										"detections": 30,
										"engines_count": 98,
										"detection_rate": "31%",
										"scantime": "0.53"
								},
								"information": {
										"reverse_dns": "dojo.census.shodan.io",
										"continent_code": "EU",
										"continent_name": "Europe",
										"country_code": "NL",
										"country_name": "Netherlands",
										"country_currency": "EUR",
										"country_calling_code": "31",
										"region_name": "Zuid-Holland",
										"city_name": "The Hague",
										"latitude": 52.0766716003418,
										"longitude": 4.298610210418701,
										"isp": "Incrediserve Ltd",
										"asn": "AS202425"
								},
								"anonymity": {
										"is_proxy": false,
										"is_webproxy": false,
										"is_vpn": false,
										"is_hosting": true,
										"is_tor": false
								},
								"risk_score": {
										"result": 100
								}
						}
				},
				"credits_remained": 96532.71,
				"estimated_queries": "1,206,658",
				"elapsed_time": "0.99",
				"success": true
			}`
			json.Unmarshal([]byte(responseReportString), &APIvoidReportData)

			expectedCSV := "IoC,BL Engine,Blacklisted\n80.82.77.139,Barracuda_Reputation_BL:http://www.barracudanetworks.com/,false\n80.82.77.139,BlockedServersRBL:https://www.blockedservers.com/,true\n"

			reports := map[string]*APIvoidReport{
				"80.82.77.139": APIvoidReportData,
			}
			actualCSV := dumpCSV(reports, triage.IPType)
			So(actualCSV, ShouldResemble, expectedCSV)
		})

		Convey("should dump proper CSV output for URL", func() {
			APIvoidReportData := &APIvoidReport{}
			responseReportString := `{
				"data": {
						"report": {
								"dns_records": {
										"ns": {
												"records": [
														{
																"target": "pdns1.ultradns.net",
																"ip": "204.74.108.1",
																"country_code": "US",
																"country_name": "United States of America",
																"isp": "UltraDNS Corporation"
														},
														{
																"target": "ns2.p31.dynect.net",
																"ip": "204.13.250.31",
																"country_code": "US",
																"country_name": "United States of America",
																"isp": "Dynamic Network Services Inc."
														}
												]
										},
										"mx": {
												"records": [
														{
																"target": "amazon-smtp.amazon.com",
																"ip": "52.119.213.152",
																"country_code": "US",
																"country_name": "United States of America",
																"isp": "Amazon Technologies Inc."
														}
												]
										}
								},
								"domain_blacklist": {
										"engines": [
												{
														"name": "ThreatLog",
														"reference": "https://www.threatlog.com/",
														"detected": false
												},
												{
														"name": "OpenPhish",
														"reference": "https://openphish.com/",
														"detected": false
												}
										],
										"detections": 0
								},
								"file_type": {
										"signature": "",
										"extension": "",
										"headers": "HTML"
								},
								"geo_location": {
										"countries": [
												"US"
										]
								},
								"html_forms": {
										"number_of_total_forms": 3,
										"number_of_total_input_fields": 8,
										"two_text_inputs_in_a_form": false,
										"credit_card_field_present": false,
										"password_field_present": false,
										"email_field_present": false
								},
								"redirection": {
										"found": false,
										"external": false,
										"url": null
								},
								"response_headers": {
										"code": 200,
										"status": "HTTP/2 200",
										"server": "Server",
										"content-type": "text/html;charset=UTF-8",
										"x-amz-rid": "PTC6HM19MX9RB6CB7D8G",
										"accept-ch-lifetime": "86400",
										"x-xss-protection": "1;",
										"cache-control": "no-cache",
										"content-encoding": "gzip",
										"content-language": "en-US",
										"x-content-type-options": "nosniff",
										"accept-ch": "ect,rtt,downlink",
										"expires": "-1",
										"x-ua-compatible": "IE=edge",
										"pragma": "no-cache",
										"strict-transport-security": "max-age=47474747; includeSubDomains; preload",
										"x-frame-options": "SAMEORIGIN",
										"permissions-policy": "interest-cohort=()",
										"date": "Sun, 26 Sep 2021 22:39:50 GMT",
										"vary": "Accept-Encoding",
										"set-cookie": "session-id=132-2632732-1637209; Domain=.amazon.com; Expires=Mon, 26-Sep-2022 22:39:50 GMT; Path=/; Secure session-id-time=2082787201l; Domain=.amazon.com; Expires=Mon, 26-Sep-2022 22:39:50 GMT; Path=/; Secure i18n-prefs=USD; Domain=.amazon.com; Expires=Mon, 26-Sep-2022 22:39:50 GMT; Path=/ lc-main=en_US; Domain=.amazon.com; Expires=Mon, 26-Sep-2022 22:39:50 GMT; Path=/ skin=noskin; path=/; domain=.amazon.com"
								},
								"risk_score": {
										"result": 0
								},
								"security_checks": {
										"is_host_an_ipv4": false,
										"is_uncommon_host_length": false,
										"is_uncommon_dash_char_count": false,
										"is_uncommon_dot_char_count": false,
										"is_suspicious_url_pattern": false,
										"is_suspicious_file_extension": false,
										"is_robots_noindex": false,
										"is_suspended_page": false,
										"is_most_abused_tld": false,
										"is_uncommon_clickable_url": false,
										"is_phishing_heuristic": false,
										"is_possible_emotet": false,
										"is_redirect_to_search_engine": false,
										"is_http_status_error": false,
										"is_http_server_error": false,
										"is_http_client_error": false,
										"is_suspicious_content": false,
										"is_url_accessible": true,
										"is_empty_page_title": false,
										"is_empty_page_content": false,
										"is_domain_blacklisted": false,
										"is_suspicious_domain": false,
										"is_sinkholed_domain": false,
										"is_defaced_heuristic": false,
										"is_masked_file": false,
										"is_risky_geo_location": false,
										"is_china_country": false,
										"is_nigeria_country": false,
										"is_non_standard_port": false,
										"is_email_address_on_url_query": false,
										"is_directory_listing": false,
										"is_exe_on_directory_listing": false,
										"is_zip_on_directory_listing": false,
										"is_php_on_directory_listing": false,
										"is_doc_on_directory_listing": false,
										"is_pdf_on_directory_listing": false,
										"is_apk_on_directory_listing": false,
										"is_linux_elf_file": false,
										"is_linux_elf_file_on_free_dynamic_dns": false,
										"is_linux_elf_file_on_free_hosting": false,
										"is_linux_elf_file_on_ipv4": false,
										"is_masked_linux_elf_file": false,
										"is_masked_windows_exe_file": false,
										"is_ms_office_file": false,
										"is_windows_exe_file_on_free_dynamic_dns": false,
										"is_windows_exe_file_on_free_hosting": false,
										"is_windows_exe_file_on_ipv4": false,
										"is_windows_exe_file": false,
										"is_android_apk_file_on_free_dynamic_dns": false,
										"is_android_apk_file_on_free_hosting": false,
										"is_android_apk_file_on_ipv4": false,
										"is_android_apk_file": false,
										"is_external_redirect": false,
										"is_risky_category": false,
										"is_domain_recent": false,
										"is_domain_very_recent": false,
										"is_credit_card_field": false,
										"is_password_field": false,
										"is_valid_https": true
								},
								"server_details": {
										"ip": "23.46.201.47",
										"hostname": "a23-46-201-47.deploy.static.akamaitechnologies.com",
										"continent_code": "NA",
										"continent_name": "North America",
										"country_code": "US",
										"country_name": "United States of America",
										"region_name": "Georgia",
										"city_name": "Atlanta",
										"latitude": 33.749000549316406,
										"longitude": -84.38797760009766,
										"isp": "Akamai Technologies Inc.",
										"asn": "AS16625"
								},
								"site_category": {
										"is_torrent": false,
										"is_vpn_provider": false,
										"is_free_hosting": false,
										"is_anonymizer": false,
										"is_url_shortener": false,
										"is_free_dynamic_dns": false
								},
								"url_parts": {
										"scheme": "https",
										"host": "www.amazon.com",
										"host_nowww": "amazon.com",
										"port": null,
										"path": null,
										"query": null
								},
								"web_page": {
										"title": "Amazon.com. Spend less. Smile more.",
										"description": "Free shipping on millions of items. Get the best of Shopping and Entertainment with Prime. Enjoy low prices and great deals on the largest selection of everyday essentials and other products, including fashion, home, beauty, electronics, Alexa Devices, sporting goods, toys, automotive, pets, baby, books, video games, musical instruments, office supplies, and more.",
										"keywords": "Amazon, Amazon.com, Books, Online Shopping, Book Store, Magazine, Subscription, Music, CDs, DVDs, Videos, Electronics, Video Games, Computers, Cell Phones, Toys, Games, Apparel, Accessories, Shoes, Jewelry, Watches, Office Products, Sports & Outdoors, Sporting Goods, Baby Products, Health, Personal Care, Beauty, Home, Garden, Bed & Bath, Furniture, Tools, Hardware, Vacuums, Outdoor Living, Automotive Parts, Pet Supplies, Broadband, DSL"
								}
						}
				},
				"credits_remained": 96533.19,
				"estimated_queries": "193,066",
				"elapsed_time": "1.48",
				"success": true
			}`
			json.Unmarshal([]byte(responseReportString), &APIvoidReportData)

			expectedCSV := "IoC,BL Engine,Blacklisted\nhttps://www.amazon.com,ThreatLog:https://www.threatlog.com/,false\nhttps://www.amazon.com,OpenPhish:https://openphish.com/,false\nDNS Records\nIoC,DNS Type,DNS Target,DNS IP,DNS ISP,DNS Address\nhttps://www.amazon.com,NS,pdns1.ultradns.net,204.74.108.1,UltraDNS Corporation,US:United States of America\nhttps://www.amazon.com,NS,ns2.p31.dynect.net,204.13.250.31,Dynamic Network Services Inc.,US:United States of America\n"

			reports := map[string]*APIvoidReport{
				"https://www.amazon.com": APIvoidReportData,
			}
			actualCSV := dumpCSV(reports, triage.URLType)
			So(actualCSV, ShouldResemble, expectedCSV)
		})

	})
}
