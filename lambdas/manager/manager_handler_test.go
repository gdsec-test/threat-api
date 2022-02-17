package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"testing"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
	. "github.com/smartystreets/goconvey/convey"
)

func TestManagerHandler(t *testing.T) {

	Convey("handler", t, func() {
		// setup stubs\mocks
		patches := []*Patches{}
		ctx1 := context.Background()
		actualDynamoDBClient := &dynamodb.DynamoDB{}
		patches = append(patches, ApplyFunc(dynamodb.New,
			func(p client.ConfigProvider, cfgs ...*aws.Config) *dynamodb.DynamoDB {
				return actualDynamoDBClient
			}))

		APIGatewayRequest := &events.APIGatewayProxyRequest{
			Path: "",
		}

		var isCreateJobCalled events.APIGatewayProxyRequest
		createJobResponse := events.APIGatewayProxyResponse{}
		patches = append(patches, ApplyFunc(createJob,
			func(box *toolbox.Toolbox, ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
				isCreateJobCalled = request
				return createJobResponse, nil
			}))

		getJobResponse := events.APIGatewayProxyResponse{}
		var isGetJobCalled events.APIGatewayProxyRequest
		patches = append(patches, ApplyFunc(getJob,
			func(ctx context.Context, request events.APIGatewayProxyRequest, jobId string) (events.APIGatewayProxyResponse, error) {
				isGetJobCalled = request
				return getJobResponse, nil
			}))

		getJobsResponse := events.APIGatewayProxyResponse{}
		var isGetJobsCalled events.APIGatewayProxyRequest
		patches = append(patches, ApplyFunc(getJobs,
			func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
				isGetJobsCalled = request
				return getJobsResponse, nil
			}))

		deleteJobResponse := events.APIGatewayProxyResponse{}
		var isDeleteJobCalled events.APIGatewayProxyRequest
		patches = append(patches, ApplyFunc(deleteJob,
			func(ctx context.Context, request events.APIGatewayProxyRequest, jobId string) (events.APIGatewayProxyResponse, error) {
				isDeleteJobCalled = request
				return deleteJobResponse, nil
			}))

		classifyIOCsResponse := events.APIGatewayProxyResponse{}
		var isClassifyIOCsCalled events.APIGatewayProxyRequest
		patches = append(patches, ApplyFunc(classifyIOCs,
			func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
				isClassifyIOCsCalled = request
				return classifyIOCsResponse, nil
			}))

		GetModulesResponse := events.APIGatewayProxyResponse{}
		var isGetModulesCalled events.APIGatewayProxyRequest
		patches = append(patches, ApplyFunc(GetModules,
			func(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
				isGetModulesCalled = request
				return GetModulesResponse, nil
			}))

		Reset(func() {
			// deferred reset all stubs\mocks after every test suite running
			for _, patch := range patches {
				patch.Reset()
			}
		})

		Convey("should return non found error if no API end point is found", func() {
			expectedResponse := events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound, Body: string("")}
			actualResponse, _ := handler(ctx1, *APIGatewayRequest)
			So(actualResponse, ShouldResemble, expectedResponse)
		})

		type TestAPICall struct {
			Name string
			Path   string
			PathParameters map[string]string
			Method string
			Result *events.APIGatewayProxyRequest
		}

		APICalls := []*TestAPICall{}
		APICalls = append(APICalls, &TestAPICall{
			"Create Job",
			"/jobs",
			map[string]string{},
			http.MethodPost,
			&isCreateJobCalled,
		})

		APICalls = append(APICalls, &TestAPICall{
			"Get single Job",
			"/jobs",
			map[string]string{
				jobIDKey: "job_id_452345",
			},
			http.MethodGet,
			&isGetJobCalled,
		})

		APICalls = append(APICalls, &TestAPICall{
			"Get many jobs",
			"/jobs",
			map[string]string{},
			http.MethodGet,
			&isGetJobsCalled,
		})

		APICalls = append(APICalls, &TestAPICall{
			"Delete job",
			"/jobs",
			map[string]string{
				jobIDKey: "job_id_4745352345",
			},
			http.MethodDelete,
			&isDeleteJobCalled,
		})

		APICalls = append(APICalls, &TestAPICall{
			"Classify IOCs",
			"/classifications",
			map[string]string{},
			http.MethodPost,
			&isClassifyIOCsCalled,
		})

		APICalls = append(APICalls, &TestAPICall{
			"Get Modules",
			"/modules",
			map[string]string{},
			http.MethodPost,
			&isGetModulesCalled,
		})

		for _, APICall := range APICalls {
			Convey("should call " + APICall.Name + " API properly by it's URL", func() {
				APIGatewayRequest.Resource = fmt.Sprintf("%d", rand.Intn(1000))
				APIGatewayRequest.Path = version + APICall.Path
				APIGatewayRequest.HTTPMethod = APICall.Method
				APIGatewayRequest.PathParameters = APICall.PathParameters
				handler(ctx1, *APIGatewayRequest)
				So(APICall.Result, ShouldResemble, APIGatewayRequest)
			})
		}

		Convey("should return error if Delete API has no Job ID", func() {
			APIGatewayRequest.Path = version + "/jobs"
			APIGatewayRequest.HTTPMethod = http.MethodDelete
			actualResponse, _ := handler(ctx1, *APIGatewayRequest)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: "Missing jobId"})
		})

		Convey("should return error if Jobs API method is not allowed or supported", func() {
			APIGatewayRequest.Path = version + "/jobs"
			APIGatewayRequest.HTTPMethod = http.MethodPatch
			actualResponse, _ := handler(ctx1, *APIGatewayRequest)
			So(actualResponse, ShouldResemble, events.APIGatewayProxyResponse{StatusCode: http.StatusMethodNotAllowed})
		})

	})
}
