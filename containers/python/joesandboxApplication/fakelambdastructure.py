class TriageData:
    def __init__(self, title: str, metadata, datatype, data):
        self.title = title
        self.metadata = metadata
        self.datatype = datatype
        self.data = data

    def to_dict(self):
        return {
            "title": self.title,
            "metadata": self.metadata,
            "datatype": self.datatype,
            "data": self.data,
        }


class RequestContext:
    def __init__(self, request_id, function_arn, condition, approximate_invoke_count):
        self.request_id = request_id
        self.function_arn = function_arn
        self.condition = condition
        self.approximate_invoke_count = approximate_invoke_count

    def to_dict(self):
        return {
            "requestId": self.request_id,
            "functionArn": self.function_arn,
            "condition": self.condition,
            "approximateInvokeCount": self.approximate_invoke_count,
        }


class ResponseContext:
    def __init__(self, status_code, executed_version):
        self.status_code = status_code
        self.executed_version = executed_version

    def to_dict(self):
        return {
            "statusCode": self.status_code,
            "executedVersion": self.executed_version,
        }


class CompletedJobData:
    def __init__(self, module_name, job_id, response):
        self.module_name = module_name
        self.job_id = job_id
        self.response = response

    def to_dict(self):
        return {
            "module_name": self.module_name,
            "jobId": self.job_id,
            "response": self.response,
        }


class FakeLambdaDestination:
    def __init__(
        self,
        version: str,
        time_stamp: str,
        request_context: RequestContext = None,
        # request_payload is an SNS event invocation object, never used in our downstream logic so not defining here
        request_payload=None,
        response_context: ResponseContext = None,
        response_payload: [CompletedJobData] = None,
    ):
        self.version = version
        self.time_stamp = time_stamp
        self.request_context = request_context
        self.request_payload = request_payload
        self.response_context = response_context
        self.response_payload = response_payload

    def to_dict(self):
        return {
            "version": self.version,
            "timestamp": self.time_stamp,
            "requestContext": self.request_context.to_dict(),
            "requestPayload": self.request_payload,
            "responseContext": self.response_context.to_dict(),
            # Decoding for just 1 data in list that's being returned by Joe Sandbox
            "responsePayload": [self.response_payload[0].to_dict()],
        }
