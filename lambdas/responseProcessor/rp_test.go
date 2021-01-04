package main

import (
	"context"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	_ "go.elastic.co/apm/module/apmlambda"
)

func TestRP(t *testing.T) {
	ctx := context.Background()
	_, err := handler(ctx, common.CompletedJobData{
		JobID:      "testJobID",
		Response:   "Response data!",
		ModuleName: "testModule",
	})
	if err != nil {
		t.Fatal(err)
	}

	// TODO: Go check dynamodb to see if the encrypted data was stored
}
