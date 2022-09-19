package main

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
)

var tb *toolbox.Toolbox

func handler(ctx context.Context, request events.SNSEvent) {
	//TODO-tanium-lambda: Start the Tanium task in ECS
	// Arguments to be passed - ctx, request that's in this function's signature
}

func main() {
	lambda.Start(handler)
}
