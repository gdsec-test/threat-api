import logging
import os

import jbxapi
import json
import polling2
import chardet
import datetime
from awsconnections import *
from fakelambdastructure import *

AWS_REGION = "us-west-2"
MODULE_NAME = "joesandbox"
API_URL = "https://jbxcloud.joesecurity.org/api"
POLLING_TIMEOUT_SECONDS = 3600  # timeout in 1 hour, also exits application with error
SAMPLE_RETRY_SECONDS = 300  # retry every 5 mins to see if the sample report is ready
ID_RETRY_SECONDS = (
    120  # retry every 2 mins to see if the web_id exists to retrieve status
)
SUCCESS_SQS_QUEUE = "JobResponses"
FAILURE_SQS_QUEUE = "JobFailures"

"""API documentation can be found at 'https://github.com/joesecurity/jbxapi/blob/master/docs/api.md' """


def configure_joesandbox() -> jbxapi.JoeSandbox:
    secrets = retrieve_secrets()
    if secrets is None:
        return None

    return jbxapi.JoeSandbox(secrets["api-key"], API_URL, True)


def list_jobs(jsb: jbxapi.JoeSandbox):
    """List jobs"""
    return jsb.analysis_list_paged()


def analysis_info(jsb: jbxapi.JoeSandbox, web_id):
    """Job and their status"""
    return jsb.analysis_info(web_id)


def retrieve_report(jsb: jbxapi.JoeSandbox, web_id, file_format):
    """Retrieve the report for a specific job"""
    return jsb.analysis_download(web_id, file_format)


def is_finished(jsb: jbxapi.JoeSandbox, web_id):
    if analysis_info(jsb, web_id)["status"] == "finished":
        return True
    return False


def is_webid_present(jsb: jbxapi.JoeSandbox, web_id):
    jobs_iterable = list_jobs(jsb)
    while True:
        try:
            # Get individual jobs from the iterable
            analysis = next(jobs_iterable)
            if analysis["webid"] == web_id:
                return True

        except StopIteration:
            break
    return False


if __name__ == "__main__":

    jsb = configure_joesandbox()

    # Set harcoded env variables for testing
    os.environ["SAMPLE_SUBMISSION_ID"] = "2705650"
    os.environ["SAMPLE_FOLDER_S3_URI"] = "quicksand/example-sample-malware/"
    os.environ["JOB_ID"] = "fake_job_id"

    # Get the web_id from env variable
    web_id = os.getenv("SAMPLE_SUBMISSION_ID")
    s3_path = os.getenv("SAMPLE_FOLDER_S3_URI")
    job_id = os.getenv("JOB_ID")

    # ------------- Wait until the webID is available -------------------

    # Poll until the web_id is updated
    if polling2.poll(
        target=lambda: is_webid_present(jsb, web_id),
        step=ID_RETRY_SECONDS,
        timeout=POLLING_TIMEOUT_SECONDS,
        check_success=polling2.is_value(True),
    ):
        print("web_id updated and available")

    # Keep polling the return values until finished
    if polling2.poll(
        target=lambda: is_finished(jsb, web_id),
        step=SAMPLE_RETRY_SECONDS,
        timeout=POLLING_TIMEOUT_SECONDS,
        check_success=polling2.is_value(True),
    ):
        print("Job completed and report as follows:")
        info = analysis_info(jsb, web_id)
        for run in info["runs"]:
            print(web_id, info["status"], run["detection"])

        print("Getting results")
        result_filename = "joe-sandbox-result.json"
        json_report = retrieve_report(jsb, web_id, "jsonfixed")
        encoding = chardet.detect(json_report[1])["encoding"]
        data = {"data": json_report[1].decode(encoding)}
        with open(result_filename, "w") as file:
            json.dump(data, file)

        # Upload the results to S3
        print("Uploading to S3")
        upload_success = upload_file_to_s3(result_filename, s3_path + result_filename)
        if upload_success:
            print("Upload to S3 successful")
            # remove the local file after uploading
            if os.path.exists(result_filename):
                os.remove(result_filename)
        else:
            print("failed to upload to S3")

        print("Converting data to match triage data")
        fake_lambda_data = FakeLambdaDestination(
            version="1.0",
            time_stamp=str(datetime.datetime.now()),
        )
        response_payload_data = CompletedJobData(
            module_name=MODULE_NAME, job_id=job_id, response=""
        )
        fake_lambda_data.response_payload = [response_payload_data]

        # Putting it in triage data for Response processor to read it
        triage_result_data = TriageData(
            title="Joe Sandbox data",
            datatype="json",
            metadata="",
            data=web_id + "  " + info["status"] + "  " + run["detection"],
        )

        response_payload_data.response = json.dumps(triage_result_data.to_dict())

        # A fake request context that the corresponding lambda would have returned
        request_context = RequestContext(
            request_id="",
            function_arn="arn:aws:lambda:us-west-2:aws-account-number:function:joesandbox",
            # the corresponding joesandbox lambda was "Successfully" invoked by sns, which subsequently started this app
            condition="Success",
            approximate_invoke_count=0,  # not used in code anywhere, just assigning the int to 0
        )
        response_context = ResponseContext(
            status_code=200,  # Considering the application succeeds
            executed_version="$LATEST",  # hard coding a fake one
        )
        fake_lambda_data.request_context = request_context
        fake_lambda_data.response_context = response_context
        # Just assigning one result in the list as joe sandbox returns one data for now ie, triage_result_data
        fake_lambda_data.response_payload = [response_payload_data]

        print("Sending data to SQS")
        # See - https://github.com/boto/botocore/issues/2705#issuecomment-1238197780 for the below env var
        os.environ["BOTO_DISABLE_COMMONNAME"] = "true"
        if write_to_sqs(SUCCESS_SQS_QUEUE, json.dumps(fake_lambda_data.to_dict())):
            print("Successfully uploaded")
