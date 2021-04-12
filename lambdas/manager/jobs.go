package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/gdcorp-infosec/threat-api/lambdas/common"
	"github.com/gdcorp-infosec/threat-api/lambdas/common/toolbox"
)

// createJob creates a new job ID in dynamo DB and sends it to the appropriate SNS topics
func createJob(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	span, ctx := to.TracerLogger.StartSpan(ctx, "CreateJob", "job", "manager", "create")
	defer span.End(ctx)

	// Generate jobId
	jobID := to.GenerateJobID(ctx)

	// Get username
	jwt, err := to.ValidateJWT(ctx, toolbox.GetJWTFromRequest(request))
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 401}, err
	}
	span.LogKV("username", jwt.BaseToken.AccountName)

	// TODO: If we want the default behavior on blank `modules` list to be launching all modules, we need to
	// check the job request and add the list of all modules if it is blank.
	// For now we require a user to submit what modules they want to run.

	// Encrypt submission
	span, ctx = to.TracerLogger.StartSpan(ctx, "EncryptSubmission", "job", "manager", "encrypt")
	encryptedData, err := to.Encrypt(ctx, jobID, []byte(request.Body))
	if err != nil {
		span.LogKV("error", err)
		span.End(ctx)
		return events.APIGatewayProxyResponse{StatusCode: 500}, fmt.Errorf("error encrypting submission: %w", err)
	}
	encryptedDataMarshalled, err := dynamodbattribute.Marshal(encryptedData)
	if err != nil {
		span.LogKV("error", err)
		span.End(ctx)
		return events.APIGatewayProxyResponse{StatusCode: 500}, fmt.Errorf("error marshalling encrypted data: %w", err)
	}
	span.End(ctx)

	// Get the SNS topic ARN
	span, ctx = to.TracerLogger.StartSpan(ctx, "GetSNSTopicInfo", "job", "sns", "getinfo")
	topicARN, err := to.GetFromParameterStore(ctx, snsTopicARNParameterName, false)
	if err != nil || topicARN.Value == nil {
		span.LogKV("error", fmt.Errorf("error getting SNS topic ARN: %w", err))
		span.End(ctx)
		return events.APIGatewayProxyResponse{StatusCode: 500}, nil
	}

	// Count total subscriptions to the SNS topic
	// Note this may only work up to 100 subscriptions
	snsClient := sns.New(to.AWSSession)
	subscriptionsOutput, err := snsClient.ListSubscriptionsByTopic(&sns.ListSubscriptionsByTopicInput{
		TopicArn: topicARN.Value,
	})
	if err != nil {
		span.LogKV("error", fmt.Errorf("error getting SNS topic subscriptions: %w", err))
		span.End(ctx)
		return events.APIGatewayProxyResponse{StatusCode: 500}, nil
	}
	totalModuleCount := len(subscriptionsOutput.Subscriptions)
	span.LogKV("SNSSubscriptionSize", totalModuleCount)
	span.End(ctx)

	// Store in database
	span, ctx = to.TracerLogger.StartSpan(ctx, "StoreJob", "job", "manager", "store")
	span.LogKV("jobId", jobID)
	_, err = dynamoDBClient.PutItem(&dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			jobIDKey:       {S: &jobID},
			usernameKey:    {S: &jwt.BaseToken.AccountName},
			"startTime":    {N: aws.String(fmt.Sprintf("%d", time.Now().Unix()))},
			"ttl":          {N: aws.String(fmt.Sprintf("%d", time.Now().Add(time.Hour*24*30).Unix()))},
			"submission":   encryptedDataMarshalled,
			"responses":    {M: map[string]*dynamodb.AttributeValue{}},
			"totalModules": {N: aws.String(fmt.Sprintf("%d", totalModuleCount))},
		},
		TableName: &to.JobDBTableName,
	})
	if err != nil {
		span.LogKV("error", err)
		span.End(ctx)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}
	span.End(ctx)

	// Send to SNS
	span, ctx = to.TracerLogger.StartSpan(ctx, "SendSNS", "job", "manager", "sendsns")

	// Marshal body
	submissionMarshalled, err := json.Marshal(common.JobSNSMessage{Submission: request, JobID: jobID})
	if err != nil {
		span.LogKV("error", err)
		span.End(ctx)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}
	submissionMarshalledString := string(submissionMarshalled)

	// Send the entire request marshalled along with the jobID
	_, err = snsClient.Publish(&sns.PublishInput{
		Message:  &submissionMarshalledString,
		TopicArn: topicARN.Value,
	})
	if err != nil {
		span.LogKV("error", err)
		span.End(ctx)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}
	span.End(ctx)

	response := struct {
		JobID string `json:"jobId"`
	}{JobID: jobID}
	responseBytes, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(responseBytes),
	}, nil
}

// deleteJob deletes a job by JobID
func deleteJob(ctx context.Context, request events.APIGatewayProxyRequest, jobID string) (events.APIGatewayProxyResponse, error) {
	span, ctx := to.TracerLogger.StartSpan(ctx, "DeleteJob", "job", "manager", "delete")
	span.LogKV("job_id", jobID)
	defer span.End(ctx)

	// Check to make sure this user owns this job

	// Check JWT
	jwt, err := to.ValidateJWT(ctx, toolbox.GetJWTFromRequest(request))
	if err != nil {
		err = fmt.Errorf("error validating jwt: %w", err)
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusUnauthorized}, err
	}

	// Search for this job under this username in the DB
	span.LogKV("username", jwt.BaseToken.AccountName)
	filter := expression.Name(usernameKey).Equal(expression.Value(jwt.BaseToken.AccountName)).And(
		expression.Name(jobIDKey).Equal(expression.Value(jobID)),
	)
	expr, err := expression.NewBuilder().WithFilter(filter).Build()
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}

	// Build modified / simplified JobDBEntry for each job
	resp, err := dynamoDBClient.Scan(&dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &to.JobDBTableName,
	})
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, fmt.Errorf("error searching for job id in db: %w", err)
	}
	if resp.Count == nil || *resp.Count == 0 {
		// This user does not own this job
		return events.APIGatewayProxyResponse{StatusCode: http.StatusForbidden}, nil
	}

	// Delete the job
	_, err = dynamoDBClient.DeleteItem(&dynamodb.DeleteItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			jobIDKey: resp.Items[0][jobIDKey],
		},
		TableName: &to.JobDBTableName,
	})
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, fmt.Errorf("error deleting job in DB: %w", err)
	}

	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, nil
}

// getJob gets the job status from dynamoDB and send it as a response
func getJob(ctx context.Context, jobID string) (events.APIGatewayProxyResponse, error) {
	span, ctx := to.TracerLogger.StartSpan(ctx, "GetJobStatus", "job", "manager", "getstatus")
	span.LogKV("jobId", jobID)
	defer span.End(ctx)

	if jobID == "" {
		return events.APIGatewayProxyResponse{StatusCode: 400}, nil
	}

	// Fetch job from database
	item, err := dynamoDBClient.GetItem(&dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			jobIDKey: {S: aws.String(jobID)},
		},
		TableName: &to.JobDBTableName,
	})
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, err
	}

	if item.Item == nil {
		return events.APIGatewayProxyResponse{StatusCode: 404}, nil
	}

	// Unmarshal the job
	jobDB := &common.JobDBEntry{}
	err = dynamodbattribute.UnmarshalMap(item.Item, jobDB)
	if err != nil {
		to.Logger.WithError(err).Error("error unmarshaling dynamodb item")
	}

	// Asherah decrypt
	jobDB.Decrypt(ctx, to)

	jobStatus, jobPercentage, err := getJobProgress(ctx, jobDB)
	if err != nil {
		to.Logger.WithError(err).Error("error getting job status")
	}

	// Marshal and reply
	responseData, err := json.Marshal(struct {
		common.JobDBEntry
		JobStatus     JobStatus `json:"jobStatus"`
		JobPercentage float64   `json:"jobPercentage"`
	}{
		JobDBEntry:    *jobDB,
		JobStatus:     jobStatus,
		JobPercentage: jobPercentage * 100,
	})
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500}, nil
	}
	return events.APIGatewayProxyResponse{StatusCode: 200, Body: string(responseData)}, nil
}

func getJobs(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	span, ctx := to.TracerLogger.StartSpan(ctx, "GetUserJobs", "job", "manager", "listuserjobs")
	defer span.End(ctx)

	jwt, err := to.ValidateJWT(ctx, toolbox.GetJWTFromRequest(request))
	if err != nil {
		err = fmt.Errorf("error validating jwt: %w", err)
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: http.StatusUnauthorized}, err
	}

	// TODO: Extract username from request
	span.LogKV("username", jwt.BaseToken.AccountName)
	filter := expression.Name(usernameKey).Equal(expression.Value(jwt.BaseToken.AccountName))
	expr, err := expression.NewBuilder().WithFilter(filter).Build()
	if err != nil {
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}

	// Build modified / simplified JobDBEntry for each job
	response := []common.JobDBEntry{}
	err = dynamoDBClient.ScanPages(&dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &to.JobDBTableName,
	}, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, entry := range page.Items {
			// This is a job is owned by this user
			jobDB := common.JobDBEntry{}
			err = dynamodbattribute.UnmarshalMap(entry, &jobDB)
			if err != nil {
				// TODO: Log?
				continue
			}
			// Decrypt because we need the original request to pull out metadata if it's there
			jobDB.Decrypt(ctx, to)

			// Remove submission data except metadata and modules list
			for key := range jobDB.DecryptedSubmission {
				switch key {
				case "metadata":
					continue
				case "modules":
					continue
				}

				delete(jobDB.DecryptedSubmission, key)
			}

			// Remove actual response data
			for moduleName := range jobDB.DecryptedResponses {
				jobDB.DecryptedResponses[moduleName] = nil
			}

			response = append(response, jobDB)
		}
		// Always get the next page
		return true
	})
	if err != nil {
		err = fmt.Errorf("error getting jobs from database: %w", err)
		span.LogKV("error", err)
		return events.APIGatewayProxyResponse{StatusCode: 500}, err
	}

	responseBytes, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(responseBytes),
	}, err
}

// getJobProgress takes a job entry and finds out it's completion state.  It will find out if the job is complete,
// or we are still waiting on modules to finish.  It will also compute the percentage complete of the job
// as len(responses) / len(modules subscribed to SNS topic)
func getJobProgress(ctx context.Context, jobEntry *common.JobDBEntry) (JobStatus, float64, error) {
	span, ctx := to.TracerLogger.StartSpan(ctx, "GetJobProgress", "job", "manager", "getprogress")
	defer span.End(ctx)

	jobStatus := JobInProgress
	switch {
	case len(jobEntry.DecryptedResponses) == jobEntry.TotalModules:
		// Job has finished all modules
		jobStatus = JobCompleted
	case time.Unix(int64(jobEntry.StartTime), 0).Before(time.Now().Add(-time.Minute * 15)):
		// Jobs have timed out at this point, job is timed out
		jobStatus = JobIncomplete
	}

	jobPercentage := float64(float64(len(jobEntry.DecryptedResponses)) / float64(jobEntry.TotalModules))

	span.LogKV("JobStatus", jobStatus)
	span.LogKV("JobPercentage", jobPercentage)

	return jobStatus, jobPercentage, nil
}
