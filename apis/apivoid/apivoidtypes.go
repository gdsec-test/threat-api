package main

type BlackListEngines []struct {
	Engine     string `json:"engine,omitempty"`
	Name       string `json:"name,omitempty"`
	Reference  string `json:"reference,omitempty"`
	Elapsed    string `json:"elapsed,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Detected   bool   `json:"detected,omitempty"`
}

type Blacklist struct {
	Engines        BlackListEngines `json:"engines,omitempty"`
	Detections     int              `json:"detections,omitempty"`
	EnginesCount   int              `json:"engines_count,omitempty"`
	DetectionsRate string           `json:"detection_rate,omitempty"`
	Scantime       string           `json:"scantime,omitempty"`
}

type APIvoidReport struct {
	Data struct {
		Report struct {
			Host        string    `json:"host,omitempty"`
			IP          string    `json:"ip,omitempty"`
			Blacklist   Blacklist `json:"blacklists,omitempty"`
			Information struct {
				ReverseDNS         string  `json:"reverse_dns,omitempty"`
				ContinentCode      string  `json:"continent_code,omitempty"`
				ContinentName      string  `json:"continent_name,omitempty"`
				CountryCode        string  `json:"country_code,omitempty"`
				CountryName        string  `json:"country_name,omitempty"`
				CountryCurrency    string  `json:"country_currency,omitempty"`
				CountryCallingCode string  `json:"country_calling_code,omitempty"`
				RegionName         string  `json:"region_name,omitempty"`
				CityName           string  `json:"city_name,omitempty"`
				Latitude           float64 `json:"latitude,omitempty"`
				Longitude          float64 `json:"longitude,omitempty"`
				Isp                string  `json:"isp,omitempty"`
				Asn                string  `json:"asn,omitempty"`
			} `json:"information,omitempty"`
			Anonymity struct {
				IsProxy    bool `json:"is_proxy,omitempty"`
				IsWebproxy bool `json:"is_webproxy,omitempty"`
				IsVpn      bool `json:"is_vpn,omitempty"`
				IsHosting  bool `json:"is_hosting,omitempty"`
				IsTor      bool `json:"is_tor,omitempty"`
			} `json:"anonymity,omitempty"`
			RiskScore struct {
				Result int `json:"result,omitempty"`
			} `json:"risk_score,omitempty"`
			Server struct {
				IP            string  `json:"ip,omitempty"`
				ReverseDNS    string  `json:"reverse_dns,omitempty"`
				ContinentCode string  `json:"continent_code,omitempty"`
				ContinentName string  `json:"continent_name,omitempty"`
				CountryCode   string  `json:"country_code,omitempty"`
				CountryName   string  `json:"country_name,omitempty"`
				RegionName    string  `json:"region_name,omitempty"`
				CityName      string  `json:"city_name,omitempty"`
				Latitude      float64 `json:"latitude,omitempty"`
				Longitude     float64 `json:"longitude,omitempty"`
				Isp           string  `json:"isp,omitempty"`
				Asn           string  `json:"asn,omitempty"`
			} `json:"server,omitempty"`
			Category struct {
				IsFreeHosting    bool `json:"is_free_hosting,omitempty"`
				IsAnonymizer     bool `json:"is_anonymizer,omitempty"`
				IsURLShortener   bool `json:"is_url_shortener,omitempty"`
				IsFreeDynamicDNS bool `json:"is_free_dynamic_dns,omitempty"`
			} `json:"category,omitempty"`
			SecurityChecks struct {
				WebsitePopularity                string `json:"website_popularity,omitempty"`
				IsHostAnIpv4                     bool   `json:"is_host_an_ipv4,omitempty"`
				IsUncommonHostLength             bool   `json:"is_uncommon_host_length,omitempty"`
				IsUncommonDashCharCount          bool   `json:"is_uncommon_dash_char_count,omitempty"`
				IsUncommonDotCharCount           bool   `json:"is_uncommon_dot_char_count,omitempty"`
				IsSuspiciousURLPattern           bool   `json:"is_suspicious_url_pattern,omitempty"`
				IsSuspiciousFileExtension        bool   `json:"is_suspicious_file_extension,omitempty"`
				IsRobotsNoindex                  bool   `json:"is_robots_noindex,omitempty"`
				IsSuspendedPage                  bool   `json:"is_suspended_page,omitempty"`
				IsMostAbusedTld                  bool   `json:"is_most_abused_tld,omitempty"`
				IsUncommonClickableURL           bool   `json:"is_uncommon_clickable_url,omitempty"`
				IsPhishingHeuristic              bool   `json:"is_phishing_heuristic,omitempty"`
				IsPossibleEmotet                 bool   `json:"is_possible_emotet,omitempty"`
				IsRedirectToSearchEngine         bool   `json:"is_redirect_to_search_engine,omitempty"`
				IsHTTPStatusError                bool   `json:"is_http_status_error,omitempty"`
				IsHTTPServerError                bool   `json:"is_http_server_error,omitempty"`
				IsHTTPClientError                bool   `json:"is_http_client_error,omitempty"`
				IsSuspiciousContent              bool   `json:"is_suspicious_content,omitempty"`
				IsURLAccessible                  bool   `json:"is_url_accessible,omitempty"`
				IsEmptyPageTitle                 bool   `json:"is_empty_page_title,omitempty"`
				IsEmptyPageContent               bool   `json:"is_empty_page_content,omitempty"`
				IsDomainBlacklisted              bool   `json:"is_domain_blacklisted,omitempty"`
				IsSuspiciousDomain               bool   `json:"is_suspicious_domain,omitempty"`
				IsSinkholedDomain                bool   `json:"is_sinkholed_domain,omitempty"`
				IsDefacedHeuristic               bool   `json:"is_defaced_heuristic,omitempty"`
				IsMaskedFile                     bool   `json:"is_masked_file,omitempty"`
				IsRiskyGeoLocation               bool   `json:"is_risky_geo_location,omitempty"`
				IsChinaCountry                   bool   `json:"is_china_country,omitempty"`
				IsNigeriaCountry                 bool   `json:"is_nigeria_country,omitempty"`
				IsNonStandardPort                bool   `json:"is_non_standard_port,omitempty"`
				IsEmailAddressOnURLQuery         bool   `json:"is_email_address_on_url_query,omitempty"`
				IsDirectoryListing               bool   `json:"is_directory_listing,omitempty"`
				IsExeOnDirectoryListing          bool   `json:"is_exe_on_directory_listing,omitempty"`
				IsZipOnDirectoryListing          bool   `json:"is_zip_on_directory_listing,omitempty"`
				IsPhpOnDirectoryListing          bool   `json:"is_php_on_directory_listing,omitempty"`
				IsDocOnDirectoryListing          bool   `json:"is_doc_on_directory_listing,omitempty"`
				IsPdfOnDirectoryListing          bool   `json:"is_pdf_on_directory_listing,omitempty"`
				IsApkOnDirectoryListing          bool   `json:"is_apk_on_directory_listing,omitempty"`
				IsLinuxElfFile                   bool   `json:"is_linux_elf_file,omitempty,omitempty"`
				IsLinuxElfFileOnFreeDynamicDNS   bool   `json:"is_linux_elf_file_on_free_dynamic_dns,omitempty"`
				IsLinuxElfFileOnFreeHosting      bool   `json:"is_linux_elf_file_on_free_hosting,omitempty"`
				IsLinuxElfFileOnIpv4             bool   `json:"is_linux_elf_file_on_ipv4,omitempty"`
				IsMaskedLinuxElfFile             bool   `json:"is_masked_linux_elf_file,omitempty"`
				IsMaskedWindowsExeFile           bool   `json:"is_masked_windows_exe_file,omitempty"`
				IsMsOfficeFile                   bool   `json:"is_ms_office_file,omitempty"`
				IsWindowsExeFileOnFreeDynamicDNS bool   `json:"is_windows_exe_file_on_free_dynamic_dns,omitempty"`
				IsWindowsExeFileOnFreeHosting    bool   `json:"is_windows_exe_file_on_free_hosting,omitempty"`
				IsWindowsExeFileOnIpv4           bool   `json:"is_windows_exe_file_on_ipv4,omitempty"`
				IsWindowsExeFile                 bool   `json:"is_windows_exe_file,omitempty"`
				IsAndroidApkFileOnFreeDynamicDNS bool   `json:"is_android_apk_file_on_free_dynamic_dns,omitempty"`
				IsAndroidApkFileOnFreeHosting    bool   `json:"is_android_apk_file_on_free_hosting,omitempty"`
				IsAndroidApkFileOnIpv4           bool   `json:"is_android_apk_file_on_ipv4,omitempty"`
				IsAndroidApkFile                 bool   `json:"is_android_apk_file,omitempty"`
				IsExternalRedirect               bool   `json:"is_external_redirect,omitempty"`
				IsRiskyCategory                  bool   `json:"is_risky_category,omitempty"`
				IsDomainRecent                   string `json:"is_domain_recent,omitempty"`
				IsDomainVeryRecent               string `json:"is_domain_very_recent,omitempty"`
				IsCreditCardField                bool   `json:"is_credit_card_field,omitempty"`
				IsPasswordField                  bool   `json:"is_password_field,omitempty"`
				IsValidHTTPS                     bool   `json:"is_valid_https,omitempty"`
			} `json:"security_checks,omitempty"`

			DNSRecords struct {
				Ns struct {
					Records []struct {
						Target      string `json:"target,omitempty"`
						IP          string `json:"ip,omitempty"`
						CountryCode string `json:"country_code,omitempty"`
						CountryName string `json:"country_name,omitempty"`
						Isp         string `json:"isp,omitempty"`
					} `json:"records,omitempty"`
				} `json:"ns,omitempty"`
				Mx struct {
					Records []struct {
						Target      string `json:"target,omitempty"`
						IP          string `json:"ip,omitempty"`
						CountryCode string `json:"country_code,omitempty"`
						CountryName string `json:"country_name,omitempty"`
						Isp         string `json:"isp,omitempty"`
					} `json:"records,omitempty"`
				} `json:"mx,omitempty"`
			} `json:"dns_records,omitempty"`
			DomainBlacklist Blacklist `json:"domain_blacklist,omitempty"`
			FileType        struct {
				Signature string `json:"signature,omitempty"`
				Extension string `json:"extension,omitempty"`
				Headers   string `json:"headers,omitempty"`
			} `json:"file_type,omitempty"`
			GeoLocation struct {
				Countries []string `json:"countries,omitempty"`
			} `json:"geo_location,omitempty"`
			HTMLForms struct {
				NumberOfTotalForms       int  `json:"number_of_total_forms,omitempty"`
				NumberOfTotalInputFields int  `json:"number_of_total_input_fields,omitempty"`
				TwoTextInputsInAForm     bool `json:"two_text_inputs_in_a_form,omitempty"`
				CreditCardFieldPresent   bool `json:"credit_card_field_present,omitempty"`
				PasswordFieldPresent     bool `json:"password_field_present,omitempty"`
				EmailFieldPresent        bool `json:"email_field_present,omitempty"`
			} `json:"html_forms,omitempty"`
			Redirection struct {
				Found    bool        `json:"found,omitempty"`
				External bool        `json:"external,omitempty"`
				URL      interface{} `json:"url,omitempty"`
			} `json:"redirection,omitempty"`
			ResponseHeaders struct {
				Code                    int    `json:"code,omitempty"`
				Status                  string `json:"status,omitempty"`
				Server                  string `json:"server,omitempty"`
				ContentType             string `json:"content-type,omitempty"`
				XAmzRid                 string `json:"x-amz-rid,omitempty"`
				AcceptChLifetime        string `json:"accept-ch-lifetime,omitempty"`
				XXSSProtection          string `json:"x-xss-protection,omitempty"`
				CacheControl            string `json:"cache-control,omitempty"`
				ContentEncoding         string `json:"content-encoding,omitempty"`
				ContentLanguage         string `json:"content-language,omitempty"`
				XContentTypeOptions     string `json:"x-content-type-options,omitempty"`
				AcceptCh                string `json:"accept-ch,omitempty"`
				Expires                 string `json:"expires,omitempty"`
				XUaCompatible           string `json:"x-ua-compatible,omitempty"`
				Pragma                  string `json:"pragma,omitempty"`
				StrictTransportSecurity string `json:"strict-transport-security,omitempty"`
				XFrameOptions           string `json:"x-frame-options,omitempty"`
				PermissionsPolicy       string `json:"permissions-policy,omitempty"`
				Date                    string `json:"date,omitempty"`
				Vary                    string `json:"vary,omitempty"`
				SetCookie               string `json:"set-cookie,omitempty"`
			} `json:"response_headers,omitempty"`
			ServerDetails struct {
				IP            string  `json:"ip,omitempty"`
				Hostname      string  `json:"hostname,omitempty"`
				ContinentCode string  `json:"continent_code,omitempty"`
				ContinentName string  `json:"continent_name,omitempty"`
				CountryCode   string  `json:"country_code,omitempty"`
				CountryName   string  `json:"country_name,omitempty"`
				RegionName    string  `json:"region_name,omitempty"`
				CityName      string  `json:"city_name,omitempty"`
				Latitude      float64 `json:"latitude,omitempty"`
				Longitude     float64 `json:"longitude,omitempty"`
				Isp           string  `json:"isp,omitempty"`
				Asn           string  `json:"asn,omitempty"`
			} `json:"server_details,omitempty"`
			SiteCategory struct {
				IsTorrent        bool `json:"is_torrent,omitempty"`
				IsVpnProvider    bool `json:"is_vpn_provider,omitempty"`
				IsFreeHosting    bool `json:"is_free_hosting,omitempty"`
				IsAnonymizer     bool `json:"is_anonymizer,omitempty"`
				IsURLShortener   bool `json:"is_url_shortener,omitempty"`
				IsFreeDynamicDNS bool `json:"is_free_dynamic_dns,omitempty"`
			} `json:"site_category,omitempty"`
			URLParts struct {
				Scheme    string      `json:"scheme,omitempty"`
				Host      string      `json:"host,omitempty"`
				HostNowww string      `json:"host_nowww,omitempty"`
				Port      interface{} `json:"port,omitempty"`
				Path      interface{} `json:"path,omitempty"`
				Query     interface{} `json:"query,omitempty"`
			} `json:"url_parts,omitempty"`
			WebPage struct {
				Title       string `json:"title,omitempty"`
				Description string `json:"description,omitempty"`
				Keywords    string `json:"keywords,omitempty"`
			} `json:"web_page,omitempty"`
		} `json:"report,omitempty"`
	} `json:"data,omitempty"`
	CreditsRemained  float64 `json:"credits_remained,omitempty"`
	EstimatedQueries string  `json:"estimated_queries,omitempty"`
	ElapsedTime      string  `json:"elapsed_time,omitempty"`
	Success          bool    `json:"success,omitempty"`
}
