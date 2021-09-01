package nvdLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
)

const (
	NVDEndpoint = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
)

type NVDReport struct {
	ResultsPerPage int `json:"resultsPerPage"`
	StartIndex     int `json:"startIndex"`
	TotalResults   int `json:"totalResults"`
	Result         struct {
		CVEDataType      string `json:"CVE_data_type"`
		CVEDataFormat    string `json:"CVE_data_format"`
		CVEDataVersion   string `json:"CVE_data_version"`
		CVEDataTimestamp string `json:"CVE_data_timestamp"`
		CVEItems         []struct {
			Cve struct {
				DataType    string `json:"data_type"`
				DataFormat  string `json:"data_format"`
				DataVersion string `json:"data_version"`
				CVEDataMeta struct {
					ID       string `json:"ID"`
					ASSIGNER string `json:"ASSIGNER"`
				} `json:"CVE_data_meta"`
				Problemtype struct {
					ProblemtypeData []struct {
						Description []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						} `json:"description"`
					} `json:"problemtype_data"`
				} `json:"problemtype"`
				References struct {
					ReferenceData []struct {
						URL       string   `json:"url"`
						Name      string   `json:"name"`
						Refsource string   `json:"refsource"`
						Tags      []string `json:"tags"`
					} `json:"reference_data"`
				} `json:"references"`
				Description struct {
					DescriptionData []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
			} `json:"cve"`
			Configurations struct {
				CVEDataVersion string `json:"CVE_data_version"`
				Nodes          []struct {
					Operator string        `json:"operator"`
					Children []interface{} `json:"children"`
					CpeMatch []struct {
						Vulnerable bool          `json:"vulnerable"`
						Cpe23URI   string        `json:"cpe23Uri"`
						CpeName    []interface{} `json:"cpe_name"`
					} `json:"cpe_match"`
				} `json:"nodes"`
			} `json:"configurations"`
			Impact struct {
				BaseMetricV3 struct {
					CvssV3 struct {
						Version               string  `json:"version, omitempty"`
						VectorString          string  `json:"vectorString, omitempty"`
						AttackVector          string  `json:"attackVector, omitempty"`
						AttackComplexity      string  `json:"attackComplexity, omitempty"`
						PrivilegesRequired    string  `json:"privilegesRequired, omitempty"`
						UserInteraction       string  `json:"userInteraction, omitempty"`
						Scope                 string  `json:"scope, omitempty"`
						ConfidentialityImpact string  `json:"confidentialityImpact, omitempty"`
						IntegrityImpact       string  `json:"integrityImpact, omitempty"`
						AvailabilityImpact    string  `json:"availabilityImpact, omitempty"`
						BaseScore             float64 `json:"baseScore, omitempty"`
						BaseSeverity          string  `json:"baseSeverity, omitempty"`
					} `json:"cvssV3, omitempty"`
					ExploitabilityScore float64 `json:"exploitabilityScore, omitempty"`
					ImpactScore         float64 `json:"impactScore, omitempty"`
				} `json:"baseMetricV3, omitempty"`
				BaseMetricV2 struct {
					CvssV2 struct {
						Version               string  `json:"version"`
						VectorString          string  `json:"vectorString"`
						AccessVector          string  `json:"accessVector"`
						AccessComplexity      string  `json:"accessComplexity"`
						Authentication        string  `json:"authentication"`
						ConfidentialityImpact string  `json:"confidentialityImpact"`
						IntegrityImpact       string  `json:"integrityImpact"`
						AvailabilityImpact    string  `json:"availabilityImpact"`
						BaseScore             float64 `json:"baseScore"`
					} `json:"cvssV2"`
					Severity                string  `json:"severity"`
					ExploitabilityScore     float64 `json:"exploitabilityScore"`
					ImpactScore             float64 `json:"impactScore"`
					AcInsufInfo             bool    `json:"acInsufInfo"`
					ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
					ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
					ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
					UserInteractionRequired bool    `json:"userInteractionRequired"`
				} `json:"baseMetricV2"`
			} `json:"impact"`
			PublishedDate    string `json:"publishedDate"`
			LastModifiedDate string `json:"lastModifiedDate"`
		} `json:"CVE_Items"`
	} `json:"result"`
}

func GetNVD(ctx context.Context, ioc string, NVDClient *http.Client) (*NVDReport, error) {
	// Build URL
	u, err := url.Parse(NVDEndpoint)
	if err != nil {
		log.Fatal("Could not connect to NVDEndpoint:", err)
		return nil, err
	}
	u.Path = path.Join(u.Path, ioc)
	URL := u.String()
	//fmt.Println(URL)

	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := NVDClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	reportHolder := &NVDReport{}
	err = json.NewDecoder(resp.Body).Decode(reportHolder)
	if err != nil {
		return nil, err
	}

	return reportHolder, nil
}
