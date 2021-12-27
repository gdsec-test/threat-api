package common

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

var responseBucket = "gd-threattools-dev-private-code-bucket"
var pathPrefix = "responses"
var expiration = 7 * 24 * time.Hour // expiration of Presigned URL set to 7 days

func PutObjectInS3(moduleName string, object io.Reader) (string, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2")},
	)
	if (err != nil) {
		fmt.Errorf("Unable to create session in AWS for S3 Upload %v\n", err)
		return "", err
	}
	cd := time.Now()
	keyName := pathPrefix + "/" + moduleName + "/" +
	 	fmt.Sprintf("%d/%d/%d/%d_%d_%d_%d", cd.Year(), cd.Month(), cd.Day(), cd.Hour(), cd.Minute(), cd.Second(), cd.Nanosecond())
	upLoadParams := &s3manager.UploadInput{
		Bucket: &responseBucket,
		Key:    &keyName,
		Body:   object,
	}
	uploader := s3manager.NewUploader(sess)
	// Perform an upload.
	result, err := uploader.UploadWithContext(context.Background(), upLoadParams)

	svc := s3.New(sess)
	req, _ := svc.GetObjectRequest(&s3.GetObjectInput{
			Bucket: aws.String(responseBucket),
			Key:    aws.String(result.Location),
	})
	urlStr, err := req.Presign(expiration)
	if err != nil {
		fmt.Errorf("Failed to Presign Object in AWS for S3 Upload %v\n", err)
	}
	return urlStr, err
}
