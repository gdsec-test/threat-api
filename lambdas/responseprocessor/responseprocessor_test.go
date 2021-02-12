package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	_ "go.elastic.co/apm/module/apmlambda"
)

func TestRP(te *testing.T) {
	ctx := context.Background()
	t = toolbox.GetToolbox()
	message := common.CompletedJobData{
		JobID:      "testJobID",
		Response:   "Response data!",
		ModuleName: "testModule",
	}
	json.NewEncoder(os.Stdout).Encode(message)
	_, err := processCompletedJob(ctx, message)
	if err != nil {
		te.Fatal(err)
	}

	// TODO: Go check dynamodb to see if the encrypted data was stored
}
