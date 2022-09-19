package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
)

func GetQueueURL(sqsClient *sqs.SQS, queue string) (*sqs.GetQueueUrlOutput, error) {
	result, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &queue,
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func SendMessage(sqsClient *sqs.SQS, queueUrl string, completedJobData string) error {
	_, err := sqsClient.SendMessage(&sqs.SendMessageInput{
		QueueUrl:    &queueUrl,
		MessageBody: aws.String(completedJobData),
	})

	return err
}

func WriteToQueue(queueName string, completedJobData string) error {

	awsSession, err := session.NewSession()
	if err != nil {
		return err
	}
	sqsClient := sqs.New(awsSession)
	urlRes, err := GetQueueURL(sqsClient, queueName)
	if err != nil {
		return err
	}

	err = SendMessage(sqsClient, *urlRes.QueueUrl, completedJobData)
	if err != nil {
		return err
	}

	return nil
}
