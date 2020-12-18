"""Lambda function to retrieve job status and output for ThreatTools API"""

import decimal
import json
import boto3


class DecimalEncoder(json.JSONEncoder):
    """Helper class to convert a DynamoDB item to JSON"""

    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            return int(o)
        return super().default(o)


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
            return {
                "statusCode": 200,
                "body": json.dumps(results["Item"], cls=DecimalEncoder),
            }

        return {"statusCode": 404, "body": json.dumps("Not Found")}

    except Exception:
        return {"statusCode": 500, "body": json.dumps("Internal Server Error")}
