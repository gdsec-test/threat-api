package main

// Mock VirusTotal Object struct

type Object struct{}

// Mock VirusTotal Object struct Methods

func (obj *Object) GetString(attr string) (s string, err error) {
	return "This is a fake response", nil
}

func (obj *Object) GetInt64(attr string) (int64, error) {
	return 1647895417, nil
}

func (obj *Object) Get(attr string) (interface{}, error) {
	var LastAnalysis interface {
		LastAnalysisMap(map[string]interface{})
	}
	if attr == "last_analysis_stats" {
		return LastAnalysis, nil
	} else {
		return nil, nil
	}
}
