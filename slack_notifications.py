import boto3
import json
import logging
import os
from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
SLACK_CHANNEL = os.environ['slackChannel']
HOOK_URL = "https://" + boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext'].decode('utf-8')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    if 'detail' in event:
        project = event["detail"]["project-name"]
        state = event["detail"]["build-status"]
        # Extract CodeBuild ID from ARN
        build_id_arn = event["detail"]["build-id"].split("/")[1]
        build_id = build_id_arn.split(":")[1]

        slack_message = {
            'channel': SLACK_CHANNEL,
            'text': "CodeBuild: %s - %s - Build ID: %s"
            % (project, state, build_id)
        }

        req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))

        try:
            response = urlopen(req)
            response.read()
            logger.info("Message posted to %s", slack_message['channel'])
        except HTTPError as e:
            logger.error("Request failed: %d %s", e.code, e.reason)
        except URLError as e:
            logger.error("Server connection failed: %s", e.reason)
        pipeline = boto3.client('codepipeline')
    # return pipeline.put_job_success_result(jobId=build_id)
    return True
