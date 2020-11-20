"""Lambda function to retrieve job status and output for ThreatTools API"""

import json
import boto3

# pylint: disable=unused-argument
def handler(event, context):
    """Lambda handler that returns an entry from the jobs DynamoDB table"""

    try:
        results = (
            boto3.resource("dynamodb")
            .Table("jobs")
            .get_item(Key={"jobId": event["pathParameters"]["jobId"]})
        )
        if "Item" in results:
            return {"statusCode": 200, "body": json.dumps(results["Item"])}

        return {"statusCode": 404, "body": json.dumps("Not Found")}

    except Exception:
        return {"statusCode": 500, "body": json.dumps("Internal Server Error")}
