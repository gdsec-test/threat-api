import logging
import os

import jbxapi
import polling2
import chardet
from awsconnections import *

AWS_REGION = "us-west-2"
MODULE_NAME = "joesandbox"
API_URL = "https://jbxcloud.joesecurity.org/api"
POLLING_TIMEOUT_SECONDS = 3600  # timeout in 1 hour, also exits application with error
SAMPLE_RETRY_SECONDS = 300  # retry every 5 mins to see if the sample report is ready
ID_RETRY_SECONDS = (
    120  # retry every 2 mins to see if the web_id exists to retrieve status
)

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

    # Get the web_id from env variable
    web_id = os.getenv("SAMPLE_SUBMISSION_ID")
    s3_path = os.getenv("SAMPLE_FOLDER_S3_URI")

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
            print("Failed to upload to S3")
