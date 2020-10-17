package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.secureserver.net/threat/util/lambda/toolbox"
)

// HandleRequest handles the main request
func HandleRequest(ctx context.Context) (string, error) {
	stuff := toolbox.GetToolbox()
	stuff.Logger.Info("Starting lambda!")
	lc, _ := lambdacontext.FromContext(ctx)
	stuff.Logger.WithField("context", lc).Info("Got lambda context")
	return fmt.Sprintf("Hello!"), nil
}

func main() {
	lambda.Start(HandleRequest)
}
