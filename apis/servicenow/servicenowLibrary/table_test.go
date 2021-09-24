// +build !runTests

package servicenowLibrary

import (
	"context"
	"fmt"
	"testing"
)

func TestGetRows(t *testing.T) {
	c, err := testingClient()
	if err != nil {
		t.Error(err)
	}

	rows := make(chan Row)
	go func() {
		err := c.GetRows(context.Background(), "", nil, rows)
		if err != nil {
			t.Error(err)
		}
	}()
	if err != nil {
		t.Error(err)
	}

	for row := range rows {
		fmt.Printf("%s\n", row)
	}
}
