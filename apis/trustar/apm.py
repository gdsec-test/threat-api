import boto3
from botocore.exceptions import ClientError
from elasticapm import Client
from starlette.applications import Starlette
from elasticapm.contrib.starlette import make_apm_client, ElasticAPM


AWS_REGION = "us-west-2"
APM_SERVER_URL = "/ThreatTools/Integrations/ELASTIC_APM_SERVER_URL"  # nosec
APM_TOKEN = "/ThreatTools/Integrations/ELASTIC_APM_SECRET_TOKEN"  # nosec


def get_secret(name, region_name):  # nosec
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=region_name)
    try:
        get_secret_value_response = client.get_secret_value(SecretId=name)
    except ClientError as e:
            print("An error occurred on service side")
    else:
        return get_secret_value_response

apm_server_url = get_secret(APM_SERVER_URL, AWS_REGION)["SecretString"]  # nosec
apm_secret_token = get_secret(APM_TOKEN, AWS_REGION)["SecretString"]  # nosec
app = Starlette()

def initAPMClient(module_name) -> Client:
    apm = make_apm_client(
        {
            "SERVICE_NAME": module_name,
            "SERVER_URL": apm_server_url,
            "SECRET_TOKEN": apm_secret_token,
            "CAPTURE_BODY": "all",
        }
    )
    app.add_middleware(ElasticAPM, client=apm)
    return apm