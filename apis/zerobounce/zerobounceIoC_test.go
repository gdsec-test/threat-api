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
		IOCs:     []string{"test@aol.com"},
		IOCsType: triage.EmailType,
	})
	triageRequests = append(triageRequests, &triage.Request{
		IOCs: []string{"aajgkgkasjdfs@gmail.com",
			"abramsunnycklj8100@gmail.com",
			"accountexec321312@caexpressevictions.com",
			"adam@circlecityacers.com",
			"adelef0jt@hotmail.com",
			"adelefernpj9@hotmail.com",
			"adelevynikki@hotmail.com",
			"admin@ng4i8r.shop",
			"adonismorrowtgff45000@gmail.com",
			"adornlaveta@hotmail.com",
			"adriana@wovendreamdesigns.com",
			"primary@amazon.com",
			"test@gmail.com",
			"adriankyleelrsf43200@gmail.com",
			"adrs67hlily@hotmail.com",
			"ags@agscircus.com",
			"ahanralmerwh93579@gmail.com",
			"ahitewil4406@gmail.com",
			"ahmadlooqwsm3360@gmail.com",
			"ain08722@gmail.com",
			"ajanae@itallifecooperative.com",
			"ajfbsasjlfansflk@gmail.com",
			"akf876876876@thisecoplanet.com",
			"aksessurga@gmail.com",
			"alan@northwalestrading.com",
			"alanaawlkelsey@hotmail.com",
			"alb5gteri@hotmail.com",
		},
		IOCsType: triage.EmailType,
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
