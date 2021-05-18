package main

import (
	"testing"
)

func TestGetIOCsTypes(t *testing.T) {
	//  TODO-regex-fix:Adding test case just for ThreatAPI failure for now
	testIocs := []string{
		"https://test.test.test.net/ls/click?upn=2O3VkQHsxfse2LMs-2FwziFzRIfeYUWZiYC6-2Bl8IM6",
		"https://test.test.test.net/ls/click?upn=2O3VkQHsxfse2LMs-2FwziFzRIfeYUWZiYC6-2Bl8I",
		"M6",
	}

	testIOCTypes := getIOCsTypes(testIocs)

	if len(testIOCTypes) == 0 {
		t.Fatal("no result returned")
	}

	if len(testIOCTypes) != 2 {
		t.Fatal("unexpected results")
	}

	// TODO-regex-fix: Improve on the assert structure
	for iocType, iocs := range testIOCTypes {
		if iocType == "MITRE_MITIGATION" {
			if iocs[0] != "M6" {
				t.Fatal("MIRE_MITIGATION classified wrong")
			}
		}
	}

}
