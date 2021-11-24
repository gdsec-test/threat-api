package sucuriLibrary

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"io"

	"github.com/techoner/gophp"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
)

var tb *toolbox.Toolbox

const (
	SucuriEndpoint = "https://monitor22.sucuri.net/scan-api.php?"
)

type SucuriReport struct {
	BLACKLIST struct {
		INFO [][]string `json:"INFO"`
	} `json:"BLACKLIST"`
	LINKS struct {
		JSLOCAL []string `json:"JSLOCAL"`
		URL     []string `json:"URL"`
	} `json:"LINKS"`
	RECOMMENDATIONS [][]string `json:"RECOMMENDATIONS"`
	SCAN            struct {
		DOMAIN []string `json:"DOMAIN"`
		IP     []string `json:"IP"`
		SITE   []string `json:"SITE"`
	} `json:"SCAN"`
	SYSTEM struct {
		INFO   []string `json:"INFO"`
		NOTICE []string `json:"NOTICE"`
	} `json:"SYSTEM"`
	VERSION struct {
		BUILDDATE    []string `json:"BUILDDATE"`
		COMPILEDDATE []string `json:"COMPILEDDATE"`
		DBDATE       []string `json:"DBDATE"`
		VERSION      []string `json:"VERSION"`
	} `json:"VERSION"`
}

func GetSucuri(ctx context.Context, ioc string, SucuriClient *http.Client) (*SucuriReport, error) {
	// Build URL
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	SucuriKey, err := tb.GetFromCredentialsStore(ctx, "ThreatTools/Integrations/sucuri", nil)
	if err != nil {
		return nil, fmt.Errorf("error getting sucuri credentials: %w", err)
	}

	secret := *SucuriKey.SecretString
	URL := SucuriEndpoint + "k=" + secret +  "&a=scan" + "&host=" + ioc + "&format=serialized"
	URL = string(URL)


	// Build request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := SucuriClient.Do(req)
	if err != nil {
		return nil, err
	}


	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	out, err := gophp.Unserialize([]byte(bodyString))

	if err != nil {
		fmt.Printf("Bad PHP unserialization %v\n", err)
		return nil, err
	}

	b, _ := json.MarshalIndent(out, "", "  ")
	reportHolder := &SucuriReport{}
	json.Unmarshal(b, reportHolder)
	//Testing Print Statements
	//fmt.Printf("%v\n", string(b))
	//fmt.Println(reportHolder.BLACKLIST.INFO[0])

	return reportHolder, nil
}
