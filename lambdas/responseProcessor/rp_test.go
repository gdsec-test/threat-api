package main

import (
	"context"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.secureserver.net/threat/util/lambda/toolbox"
	_ "go.elastic.co/apm/module/apmlambda"
)

func TestRP(te *testing.T) {
	ctx := context.Background()
	t = toolbox.GetToolbox()
	_, err := processCompletedJob(ctx, common.CompletedJobData{
		JobID:      "testJobID",
		Response:   "Response data!",
		ModuleName: "testModule",
	})
	if err != nil {
		te.Fatal(err)
	}

	// TODO: Go check dynamodb to see if the encrypted data was stored
}
