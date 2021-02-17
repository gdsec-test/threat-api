package toolbox

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

func getTestingAWSSession(ctx context.Context, t *Toolbox) {

	// Load session
	// You need these env vars set
	// "AWS_ACCESS_KEY_ID"
	// "AWS_SECRET_ACCESS_KEY"
	// "AWS_SESSION_TOKEN"
	// You can get them by running this command
	// aws-okta-processor authenticate -d 7200 -e -o godaddy.okta.com -u your_godaddy_username -k okta
	c := credentials.NewEnvCredentials()
	t.LoadAWSSession(c, "us-west-2")
}

func TestGetParameter(t *testing.T) {
	toolbox := GetToolbox()
	ctx := context.Background()
	getTestingAWSSession(ctx, toolbox)

	// Get parameter
	parameter, err := toolbox.GetFromParameterStore(ctx, "TestParameter", false)
	if err != nil {
		t.Error(err)
		return
	}

	if *parameter.Value != "Test" {
		t.Errorf("did not get expected parameter value: %s", *parameter.Value)
	}
}
