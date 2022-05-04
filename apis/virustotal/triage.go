package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"math"
	"strconv"
	"time"

	vt "github.com/VirusTotal/vt-go"
	vtlib "github.com/gdcorp-infosec/threat-api/apis/virustotal/virustotalLibrary"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox/appsectracing"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

const (
	triageModuleName     = "virustotal"
	secretID             = "/ThreatTools/Integrations/virustotal"
	badnessScalingFactor = 1.0 / 7.0
	reputationComponent  = 0.2
	analysisComponent    = 0.8
)

type VirusTotalAnalysis struct {
	harmless   int64
	malicious  int64
	suspicious int64
	timeout    int64
	undetected int64
}

func (m VirusTotalAnalysis) GetAnalysesCount() int64 {
	return m.harmless + m.malicious + m.suspicious + m.timeout + m.undetected
}

// Triage module
type TriageModule struct {
}

// Mock interface for external VirusTotal library Object (vt.Object)
type VirusTotalObject interface {
	GetInt64(attr string) (int64, error)
	GetString(attr string) (s string, err error)
	Get(attr string) (interface{}, error)
}

// GetDocs of this module
func (m *TriageModule) GetDocs() *triage.Doc {
	return &triage.Doc{Name: triageModuleName, Description: "Return information about scanned files and URLs from VirusTotal."}
}

// Supports returns true if we support this IoC type
func (m *TriageModule) Supports() []triage.IOCType {
	return []triage.IOCType{
		triage.DomainType,
		triage.IPType,
		triage.URLType,
		triage.MD5Type,
		triage.SHA1Type,
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

	metaDataHolder := vtlib.InitializeLastAnalysisMetaData() // Initialize empty metadata holder
	var entries []*vt.Object                                 // Initialize slice of entries
	switch triageRequest.IOCsType {
	case triage.MD5Type, triage.SHA256Type:
		for _, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetHash(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries = append(entries, entry)
		}
		entriesVTObject := covertToVTObject(entries)
		triageData.Data = HashesToCsv(entriesVTObject, metaDataHolder)
		triageData.Metadata = []string{fmt.Sprintf("Found %d matching %s hashes", len(entries), triageRequest.IOCsType)}
	case triage.DomainType:
		for _, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetDomain(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries = append(entries, entry)
		}
		entriesVTObject := covertToVTObject(entries)
		triageData.Data = DomainsToCsv(entriesVTObject, metaDataHolder)
		triageData.Metadata = []string{fmt.Sprintf("Found %d matching domains", len(entries))}
	case triage.IPType:
		for _, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetAddress(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries = append(entries, entry)
		}
		entriesVTObject := covertToVTObject(entries)
		triageData.Data = IpsToCsv(entriesVTObject, metaDataHolder)
		triageData.Metadata = []string{fmt.Sprintf("Found %d matching IP address", len(entries))}
	case triage.URLType:
		for _, ioc := range triageRequest.IOCs {
			entry, err := virusTotal.GetURL(ctx, ioc)
			if err != nil {
				fmt.Println(err)
				continue
			}
			entries = append(entries, entry)
		}
		entriesVTObject := covertToVTObject(entries)
		triageData.Data = UrlsToCsv(entriesVTObject, metaDataHolder)
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

func BadnessScore(reputation int64, analysis *VirusTotalAnalysis) float64 {
	reputation_normalized := math.Tanh(math.Max(-float64(reputation), 0.0) * badnessScalingFactor)
	analysis_normalized := float64(analysis.malicious) / float64(analysis.GetAnalysesCount())
	return reputation_normalized*reputationComponent + analysis_normalized*analysisComponent
}

// Dump the relevant fields from the VirusTotal Object returned by
// the files interface into CSV format.
func HashesToCsv(payloads []VirusTotalObject, metaDataHolder *vtlib.MetaData) string {
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
		"Badness",
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
		badness := 0.0
		var analysis *VirusTotalAnalysis
		lastAnalysis, err := payload.Get("last_analysis_stats")
		if err != nil {
			lastAnalysisMap := lastAnalysis.(map[string]interface{})
			analysis = getLastAnalysisStats(lastAnalysisMap)
			badness = BadnessScore(reputation, analysis)
		}

		cols := []string{
			md5,
			sha1,
			sha256,
			magic,
			strconv.FormatInt(size, 10),
			firstSeen,
			strconv.FormatInt(reputation, 10),
			strconv.FormatInt(analysis.harmless, 10),
			strconv.FormatInt(analysis.malicious, 10),
			strconv.FormatInt(analysis.suspicious, 10),
			strconv.FormatInt(analysis.timeout, 10),
			strconv.FormatInt(analysis.undetected, 10),
			strconv.FormatFloat(badness, 'f', 2, 64),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

// Dump the relevant fields from the VirusTotal Object returned by
// the domains interface into CSV format.
func DomainsToCsv(payloads []VirusTotalObject, metaDataHolder *vtlib.MetaData) string {
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
		"Badness",
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
		badness := 0.0
		var analysis *VirusTotalAnalysis
		lastAnalysis, err := payload.Get("last_analysis_stats")
		if err == nil && lastAnalysis != nil {
			lastAnalysisMap := lastAnalysis.(map[string]interface{})
			analysis = getLastAnalysisStats(lastAnalysisMap)
			badness = BadnessScore(reputation, analysis)
		}

		cols := []string{
			creationDate,
			strconv.FormatInt(reputation, 10),
			whois,
			strconv.FormatInt(analysis.harmless, 10),
			strconv.FormatInt(analysis.malicious, 10),
			strconv.FormatInt(analysis.suspicious, 10),
			strconv.FormatInt(analysis.timeout, 10),
			strconv.FormatInt(analysis.undetected, 10),
			strconv.FormatFloat(badness, 'f', 2, 64),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

// Dump the relevant fields from the VirusTotal Object returned by
// the ip_addresses interface into CSV format.
func IpsToCsv(payloads []VirusTotalObject, metaDataHolder *vtlib.MetaData) string {
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
		"Badness",
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
		reputation, err := payload.GetInt64("reputation")
		if err != nil {
			fmt.Println(err)
			continue
		}
		badness := 0.0
		var analysis *VirusTotalAnalysis
		lastAnalysis, err := payload.Get("last_analysis_stats")
		if err != nil {
			lastAnalysisMap := lastAnalysis.(map[string]interface{})
			analysis = getLastAnalysisStats(lastAnalysisMap)
			badness = BadnessScore(reputation, analysis)
		}

		cols := []string{
			owner,
			strconv.FormatInt(asn, 10),
			country,
			strconv.FormatInt(analysis.harmless, 10),
			strconv.FormatInt(analysis.malicious, 10),
			strconv.FormatInt(analysis.suspicious, 10),
			strconv.FormatInt(analysis.timeout, 10),
			strconv.FormatInt(analysis.undetected, 10),
			strconv.FormatFloat(badness, 'f', 2, 64),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

// Dump the relevant fields from the VirusTotal Object returned by
// the urls interface into CSV format.
func UrlsToCsv(payloads []VirusTotalObject, metaDataHolder *vtlib.MetaData) string {
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
		"Badness",
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
		badness := 0.0
		var analysis *VirusTotalAnalysis
		lastAnalysis, err := payload.Get("last_analysis_stats")
		if err != nil {
			lastAnalysisMap := lastAnalysis.(map[string]interface{})
			analysis = getLastAnalysisStats(lastAnalysisMap)
			badness = BadnessScore(reputation, analysis)
		}

		cols := []string{
			url,
			title,
			strconv.FormatInt(reputation, 10),
			firstSubmission,
			strconv.FormatInt(analysis.harmless, 10),
			strconv.FormatInt(analysis.malicious, 10),
			strconv.FormatInt(analysis.suspicious, 10),
			strconv.FormatInt(analysis.timeout, 10),
			strconv.FormatInt(analysis.undetected, 10),
			strconv.FormatFloat(badness, 'f', 2, 64),
		}
		csv.Write(cols)
	}
	csv.Flush()

	return resp.String()
}

func getLastAnalysisStats(lastAnalysisMap map[string]interface{}) *VirusTotalAnalysis {
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
	analysis := new(VirusTotalAnalysis)
	analysis.harmless = harmless
	analysis.malicious = malicious
	analysis.suspicious = suspicious
	analysis.timeout = timeout
	analysis.undetected = undetected
	return analysis
}

// Helper method to convert a slice of entries (vt.Object type) to a slice of VirusTotalObject entries
func covertToVTObject(entries []*vt.Object) []VirusTotalObject {
	entriesVTObject := make([]VirusTotalObject, len(entries))
	for i, entry := range entries {
		entriesVTObject[i] = entry
	}
	return entriesVTObject
}
