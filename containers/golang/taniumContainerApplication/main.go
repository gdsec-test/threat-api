package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/triagelegacyconnector/triage"
	"net/http"
	"os"
	"strings"
	"time"
)

//var tb *toolbox.Toolbox

// TriageModule triage module
type TriageModule struct {
	TaniumClient *http.Client
}

type FakeLambdaDestination struct {
	Version        string `json:"version"`
	Timestamp      string `json:"timestamp"`
	RequestContext struct {
		RequestID              string `json:"requestId"`
		FunctionArn            string `json:"functionArn"`
		Condition              string `json:"condition"`
		ApproximateInvokeCount int64  `json:"approximateInvokeCount"`
	} `json:"requestContext"`
	RequestPayload  events.SNSEvent `json:"requestPayload"`
	ResponseContext struct {
		StatusCode      int64  `json:"statusCode"`
		ExecutedVersion string `json:"executedVersion"`
	} `json:"responseContext"`
	// Note that a completed job can contain data for multiple jobs, that is
	// why this is an array
	ResponsePayload CompletedJobDataList `json:"responsePayload"`
}

// CompletedJobDataList is a list of completed job datas, we define this extra structure
// to write our own unmarshaller
type CompletedJobDataList []common.CompletedJobData

func appTrigger(ctx context.Context, iocList []string, iocType string) ([]*triage.Data, error) {
	//tb = toolbox.GetToolbox()
	//defer tb.Close(ctx)

	taniumTriageModule := TriageModule{TaniumClient: http.DefaultClient}

	return taniumTriageModule.Triage(ctx, iocList, iocType)
}

// Triage retrieves data by talking to the Tanium library
func (m *TriageModule) Triage(ctx context.Context, iocList []string, iocType string) ([]*triage.Data, error) {

	//tb = toolbox.GetToolbox()
	//defer tb.Close(ctx)
	//
	//var span *appsectracing.Span
	//span, ctx = tb.TracerLogger.StartSpan(ctx, "Tanium", "triage", "questionquery", "get")
	//defer span.End(ctx)

	result, err := m.SubmitTaniumQuestion(ctx, iocList, iocType)

	return result, err
}

func main() {
	fmt.Println("Tanium application is running .... ")
	ctx := context.Background()

	//os.Setenv("IOC_LIST", "cpe:2.3:a:microsoft:edge:-:*:*:*:*:*:*:**")
	//os.Setenv("IOC_TYPE", "CPE")
	//os.Setenv("JOB_ID", "")
	//os.Setenv("MODULE_NAME", "tanium")

	IoCListString := os.Getenv("IOC_LIST")
	IoCList := strings.Split(IoCListString, ",")

	IoCType := os.Getenv("IOC_TYPE")
	JobID := os.Getenv("JOB_ID")
	moduleName := os.Getenv("MODULE_NAME")

	fmt.Println("All the environmental variables read are printed below : ")
	fmt.Println(IoCListString)
	fmt.Println(IoCType)
	fmt.Println(JobID)
	fmt.Println(moduleName)

	completedData := FakeLambdaDestination{
		Version:   "1.0",
		Timestamp: time.Now().String(),
	}

	response := common.CompletedJobData{
		ModuleName: moduleName,
		JobID:      JobID,
		Response:   "",
	}

	triageDatas, err := appTrigger(ctx, IoCList, IoCType)
	if err != nil {
		err = fmt.Errorf("this module had an error processing this request: %s", err)
		completedData.RequestContext.Condition = "Failure"
		response.Response = err.Error()
	}

	triageDataMarshal, err := json.Marshal(triageDatas)
	if err != nil {
		err = fmt.Errorf("error marshalling the triage data: %w", err)
		response.Response = err.Error()
		completedData.RequestContext.Condition = "Failure"
	}

	response.Response = string(triageDataMarshal)
	completedData.ResponsePayload = append(completedData.ResponsePayload, response)

	// Setting it to success before marshalling
	completedData.RequestContext.Condition = "Success"

	queueResults, err := json.Marshal(completedData)
	if err != nil {
		fmt.Println("errored out during marshaling data")
		return
	}

	if completedData.RequestContext.Condition == "Failure" {
		fmt.Println("Writing results to failed SQS")
		WriteToQueue("JobFailures", string(queueResults))
		return
	}
	fmt.Println("Writing results to success SQS", string(queueResults))
	WriteToQueue("JobResponses", string(queueResults))
}
