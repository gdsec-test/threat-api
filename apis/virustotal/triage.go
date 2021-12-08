package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strconv"
	"time"

	vt "github.com/VirusTotal/vt-go"
	vtlib "github.com/gdcorp-infosec/threat-api/apis/virustotal/virustotalLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	triageModuleName = "virustotal"
	secretID         = "/ThreatTools/Integrations/virustotal"
)

// Triage module
type TriageModule struct {
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Return information about scanned filed and URLs from VirusTotal."}
}

// Supports returns true of we support this IoC type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{
		triage.DomainType,
		triage.IPType,
		triage.URLType,
		triage.MD5Type,
		triage.SHA256Type,
	}
}

func (m *TriageModule) ProcessRequest(ctx context.Context, triageRequest *triage.Request, apiKey string) (*triage.Data, error) {
	triageData := &triage.Data{
		Title:    "VirusTotal",
		Metadata: []string{},
	}
	tb := toolbox.GetToolbox()
	virusTotal := vtlib.NewVirusTotal(tb, apiKey)

	// Initialize empty metadata holder
	metaDataHolder := vtlib.InitializeLastAnalysisMetaData()

	switch triageRequest.IOCsType {
	case triage.MD5Type, triage.SHA256Type:
		var entries []*vt.Object
		for _, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetHash(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries = append(entries, entry)
		}
		triageData.Data = HashesToCsv(entries, metaDataHolder)
		triageData.Metadata = []string{fmt.Sprintf("Found %d matching %s hashes", len(entries), triageRequest.IOCsType)}
	case triage.DomainType:
		var entries []*vt.Object
		for _, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetDomain(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries = append(entries, entry)
		}
		triageData.Data = DomainsToCsv(entries, metaDataHolder)
		triageData.Metadata = []string{fmt.Sprintf("Found %d matching domains", len(entries))}
	case triage.IPType:
		var entries []*vt.Object
		for _, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetAddress(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries = append(entries, entry)
		}
		triageData.Data = IpsToCsv(entries, metaDataHolder)
		triageData.Metadata = []string{fmt.Sprintf("Found %d matching IP address", len(entries))}
	case triage.URLType:
		var entries []*vt.Object
		for _, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetURL(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries = append(entries, entry)
		}
		triageData.Data = UrlsToCsv(entries, metaDataHolder)
		triageData.Metadata = []string{fmt.Sprintf("Found %d matching URLs", len(entries))}
	}
	currentTime := time.Now()
	triageData.Metadata = append(triageData.Metadata, fmt.Sprintf("The last analysis run on %s returned scan result counts of (harmless/malicious/suspicious/timeout/undetected): %d / %d / %d / %d / %d", currentTime.Format("2006-January-02"), metaDataHolder.Harmless, metaDataHolder.Malicious, metaDataHolder.Suspicious, metaDataHolder.Timeout, metaDataHolder.Undetected))

	return triageData, nil
}

func (m *TriageModule) Triage(ctx context.Context, triageRequest *triage.Request) ([]*triage.Data, error) {
	tb := toolbox.GetToolbox()
	defer tb.Close(ctx)
	var span *appsectracing.Span
	span, ctx = tb.TracerLogger.StartSpan(ctx, "TriageVT", "virustotal", "", "triage")
	defer span.End(ctx)

	triageData := &triage.Data{
		Title:    "VirusTotal",
		Metadata: []string{},
	}

	// Get the API key from
	span, _ = tb.TracerLogger.StartSpan(ctx, "GetAPIKey", "virustotal", "", "getapikey")
	secret, err := tb.GetFromCredentialsStore(ctx, secretID, nil)
	if err != nil {
		span.AddError(err)
		span.End(ctx)
		triageData.Data = fmt.Sprintf("Error retrieving secret with key, %s: %s", secretID, err)
		return []*triage.Data{triageData}, err
	}
	apiKey := *secret.SecretString
	span.End(ctx)

	// Process the request by querying each API endpoint per IoC type
	span, _ = tb.TracerLogger.StartSpan(ctx, "ProcessRequest", "virustotal", "", "processrequest")
	data, err := m.ProcessRequest(ctx, triageRequest, apiKey)
	if err != nil {
		span.AddError(err)
		span.End(ctx)
		return nil, err
	}
	span.End(ctx)

	// Return the data
	data.DataType = triage.CSVType
	return []*triage.Data{data}, nil
}

// Dump the relevant fields from the VirusTotal Object returned by
// the files interface into CSV format.
func HashesToCsv(payloads []*vt.Object, metaDataHolder *vtlib.MetaData) string {
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)

	csv.Write([]string{
		"MD5",
		"SHA1",
		"SHA256",
		"Magic",
		"File Size",
		"First Seen",
		"Reputation",
		"Harmless",
		"Malicious",
		"Suspicious",
		"Timeout",
		"Undetected",
	})

	for _, payload := range payloads {
		if payload == nil {
			continue
		}

		// convert the "first seen in the wild" field from
		// the Linux epoch time as an integer into a RFC 3339 string
		firstSeenEpoch, err := payload.GetInt64("first_seen_itw_date")
		if err != nil {
			fmt.Println(err)
			continue
		}
		t := time.Unix(firstSeenEpoch, 0)
		firstSeen := t.Format(time.RFC3339)

		md5, err := payload.GetString("md5")
		if err != nil {
			fmt.Println(err)
			continue
		}
		sha1, err := payload.GetString("sha1")
		if err != nil {
			fmt.Println(err)
			continue
		}
		sha256, err := payload.GetString("sha256")
		if err != nil {
			fmt.Println(err)
			continue
		}
		magic, err := payload.GetString("magic")
		if err != nil {
			fmt.Println(err)
			continue
		}
		size, err := payload.GetInt64("size")
		if err != nil {
			fmt.Println(err)
			continue
		}
		reputation, err := payload.GetInt64("reputation")
		if err != nil {
			fmt.Println(err)
			continue
		}
		lastAnalysis, err := payload.Get("last_analysis_stats")
		var harmless, malicious, suspicious, timeout, undetected int64
		if err != nil {
			lastAnalysisMap := lastAnalysis.(map[string]interface{})
			harmless, malicious, suspicious, timeout, undetected = getLastAnalysisStats(lastAnalysisMap)
			updateMetaData(metaDataHolder, harmless, malicious, suspicious, timeout, undetected)
		}

		updateMetaData(metaDataHolder, harmless, malicious, suspicious, timeout, undetected)

		cols := []string{
			md5,
			sha1,
			sha256,
			magic,
			strconv.FormatInt(size, 10),
			firstSeen,
			strconv.FormatInt(reputation, 10),
			strconv.FormatInt(harmless, 10),
			strconv.FormatInt(malicious, 10),
			strconv.FormatInt(suspicious, 10),
			strconv.FormatInt(timeout, 10),
			strconv.FormatInt(undetected, 10),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

// Dump the relevant fields from the VirusTotal Object returned by
// the domains interface into CSV format.
func DomainsToCsv(payloads []*vt.Object, metaDataHolder *vtlib.MetaData) string {
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)

	csv.Write([]string{
		"Created",
		"Reputation",
		"WHOIS",
		"Harmless",
		"Malicious",
		"Suspicious",
		"Timeout",
		"Undetected",
	})

	for _, payload := range payloads {
		if payload == nil {
			continue
		}

		// convert the creation date field from
		// the Linux epoch time as an integer into a RFC 3339 string
		creationDateEpoch, err := payload.GetInt64("creation_date")
		if err != nil {
			fmt.Println(err)
			continue
		}
		t := time.Unix(creationDateEpoch, 0)
		creationDate := t.Format(time.RFC3339)

		whois, err := payload.GetString("whois")
		if err != nil {
			fmt.Println(err)
			continue
		}
		reputation, err := payload.GetInt64("reputation")
		if err != nil {
			fmt.Println(err)
			continue
		}
		lastAnalysis, err := payload.Get("last_analysis_stats")
		var harmless, malicious, suspicious, timeout, undetected int64
		if err == nil {
			lastAnalysisMap := lastAnalysis.(map[string]interface{})
			harmless, malicious, suspicious, timeout, undetected = getLastAnalysisStats(lastAnalysisMap)
			updateMetaData(metaDataHolder, harmless, malicious, suspicious, timeout, undetected)
		}

		cols := []string{
			creationDate,
			strconv.FormatInt(reputation, 10),
			whois,
			strconv.FormatInt(harmless, 10),
			strconv.FormatInt(malicious, 10),
			strconv.FormatInt(suspicious, 10),
			strconv.FormatInt(timeout, 10),
			strconv.FormatInt(undetected, 10),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

// Dump the relevant fields from the VirusTotal Object returned by
// the ip_addresses interface into CSV format.
func IpsToCsv(payloads []*vt.Object, metaDataHolder *vtlib.MetaData) string {
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)

	csv.Write([]string{
		"Owner",
		"ASN",
		"Country",
		"Harmless",
		"Malicious",
		"Suspicious",
		"Timeout",
		"Undetected",
	})

	for _, payload := range payloads {
		if payload == nil {
			continue
		}

		owner, err := payload.GetString("as_owner")
		if err != nil {
			fmt.Println(err)
			continue
		}
		asn, err := payload.GetInt64("asn")
		if err != nil {
			fmt.Println(err)
			continue
		}
		country, err := payload.GetString("country")
		if err != nil {
			fmt.Println(err)
			continue
		}
		lastAnalysis, err := payload.Get("last_analysis_stats")
		var harmless, malicious, suspicious, timeout, undetected int64
		if err != nil {
			lastAnalysisMap := lastAnalysis.(map[string]interface{})
			harmless, malicious, suspicious, timeout, undetected = getLastAnalysisStats(lastAnalysisMap)
			updateMetaData(metaDataHolder, harmless, malicious, suspicious, timeout, undetected)
		}

		updateMetaData(metaDataHolder, harmless, malicious, suspicious, timeout, undetected)

		cols := []string{
			owner,
			strconv.FormatInt(asn, 10),
			country,
			strconv.FormatInt(harmless, 10),
			strconv.FormatInt(malicious, 10),
			strconv.FormatInt(suspicious, 10),
			strconv.FormatInt(timeout, 10),
			strconv.FormatInt(undetected, 10),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

// Dump the relevant fields from the VirusTotal Object returned by
// the urls interface into CSV format.
func UrlsToCsv(payloads []*vt.Object, metaDataHolder *vtlib.MetaData) string {
	resp := bytes.Buffer{}
	csv := csv.NewWriter(&resp)

	csv.Write([]string{
		"URL",
		"Title",
		"Reputation",
		"First Submission",
		"Harmless",
		"Malicious",
		"Suspicious",
		"Timeout",
		"Undetected",
	})

	for _, payload := range payloads {
		if payload == nil {
			continue
		}

		// convert the first submission date field from
		// the Linux epoch time as an integer into a RFC 3339 string
		firstSubmissionEpoch, err := payload.GetInt64("first_submission_date")
		if err != nil {
			fmt.Println(err)
			continue
		}
		t := time.Unix(firstSubmissionEpoch, 0)
		firstSubmission := t.Format(time.RFC3339)

		url, err := payload.GetString("url")
		if err != nil {
			fmt.Println(err)
			continue
		}
		title, err := payload.GetString("title")
		if err != nil {
			// some legitimate results omit a title field
			title = ""
		}
		reputation, err := payload.GetInt64("reputation")
		if err != nil {
			fmt.Println(err)
			continue
		}
		lastAnalysis, err := payload.Get("last_analysis_stats")
		var harmless, malicious, suspicious, timeout, undetected int64
		if err != nil {
			lastAnalysisMap := lastAnalysis.(map[string]interface{})
			harmless, malicious, suspicious, timeout, undetected = getLastAnalysisStats(lastAnalysisMap)
			updateMetaData(metaDataHolder, harmless, malicious, suspicious, timeout, undetected)
		}

		updateMetaData(metaDataHolder, harmless, malicious, suspicious, timeout, undetected)

		cols := []string{
			url,
			title,
			strconv.FormatInt(reputation, 10),
			firstSubmission,
			strconv.FormatInt(harmless, 10),
			strconv.FormatInt(malicious, 10),
			strconv.FormatInt(suspicious, 10),
			strconv.FormatInt(timeout, 10),
			strconv.FormatInt(undetected, 10),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

func getLastAnalysisStats(lastAnalysisMap map[string]interface{}) (int64, int64, int64, int64, int64) {
	var harmless int64
	if fmt.Sprintf("%T", lastAnalysisMap["harmless"]) == "float64" {
		harmless = int64(lastAnalysisMap["harmless"].(float64))
	}
	var malicious int64
	if fmt.Sprintf("%T", lastAnalysisMap["malicious"]) == "float64" {
		malicious = int64(lastAnalysisMap["malicious"].(float64))
	}
	var suspicious int64
	if fmt.Sprintf("%T", lastAnalysisMap["suspicious"]) == "float64" {
		suspicious = int64(lastAnalysisMap["suspicious"].(float64))
	}
	var timeout int64
	if fmt.Sprintf("%T", lastAnalysisMap["timeout"]) == "float64" {
		timeout = int64(lastAnalysisMap["timeout"].(float64))
	}
	var undetected int64
	if fmt.Sprintf("%T", lastAnalysisMap["undetected"]) == "float64" {
		undetected = int64(lastAnalysisMap["undetected"].(float64))
	}
	return harmless, malicious, suspicious, timeout, undetected
}

func updateMetaData(metaDataHolder *vtlib.MetaData, harmless int64, malicious int64, suspicious int64, timeout int64, undetected int64) {
	metaDataHolder.Harmless += harmless
	metaDataHolder.Malicious += malicious
	metaDataHolder.Suspicious += suspicious
	metaDataHolder.Timeout += timeout
	metaDataHolder.Undetected += undetected
}
