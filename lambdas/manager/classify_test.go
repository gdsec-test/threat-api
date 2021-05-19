package main

import (
	"reflect"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
)

func TestGetIOCsTypes(t *testing.T) {
	tests := map[triage.IOCType][]string{
		triage.URLType:               {"https://test.net/click?upn=2O3VkQHsxfsYUWZiYC6-2Bl8IM6", "https://test.net/click?upn=2O3VkQHsxfsYUWZiYC6-2Bl8I"},
		triage.MitreMatrixType:       {"MA1056"},
		triage.MitreTacticType:       {"TA0043"},
		triage.MitreTechniqueType:    {"T1548"},
		triage.MitreSubTechniqueType: {"T1548.004"},
		triage.MitreMitigationType:   {"M1015"},
		triage.MitreGroupType:        {"G0130"},
		triage.MitreSoftwareType:     {"S0066"},
		triage.UnknownType:           {"M6"},
	}

	var testIOCs []string
	for _, test := range tests {
		testIOCs = append(testIOCs, test...)
	}

	results := getIOCsTypes(testIOCs)

	if !reflect.DeepEqual(tests, results) {
		t.Fatal("results don't match")
	}
}
