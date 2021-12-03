package main

import (
	"context"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestGetExampleData(t *testing.T) {

	ctx := context.Background()
	tb = toolbox.GetToolbox()
	defer tb.Close(ctx)

	var triageRequests []*triage.Request

	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"seguro.emporiobrazil24h.com/cart", "https://pi-mars.com/", "https://discord-fonts.com/", "outlook.live.com/owa/"},
		IOCsType: triage.URLType,
	})

	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"https://gmail.com/", "162.241.2.44/404.html", "www.shorturl.at/"},
		IOCsType: triage.URLType,
	})

	triageRequests = append(triageRequests, &triage.Request{
		IOCs:     []string{"https://facebook.com/"},
		IOCsType: triage.URLType,
	})

	for _, triageRequest := range triageRequests {
		triageModule := TriageModule{}
		triageResult, err := triageModule.Triage(ctx, triageRequest)
		if err != nil {
			t.Fatal(err)
		}

		if len(triageResult) == 0 {
			t.Fatal("len 0")
		}
		if triageResult[0].Data == "" {
			t.Fatal("first data element empty ")
		}
	}
}
