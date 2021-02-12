package toolbox

import (
	"reflect"
	"testing"
)

func TestGetToolbox(t *testing.T) {
	// Test to make sure defaults are being set properly
	toolbox := GetToolbox()

	// Check defaults
	typeOf := reflect.TypeOf(*toolbox)
	valueOf := reflect.Indirect(reflect.ValueOf(toolbox))
	for i := 0; i < typeOf.NumField(); i++ {
		if typeOf.Field(i).Type.Kind() != reflect.String {
			// Only check string fields
			continue
		}
		defaultValue := typeOf.Field(i).Tag.Get("default")
		if valueOf.Field(i).String() != defaultValue {
			t.Errorf("Field %s does not have default value (%s instead of %s)", typeOf.Field(i).Name, valueOf.Field(i).String(), defaultValue)
		}
	}

	// Check http client
	if toolbox.client == nil {
		t.Errorf("http client is nil")
	}
}
