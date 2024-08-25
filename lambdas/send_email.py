import json
import boto3

ses_client = boto3.client('ses')


def handler(event, context):
    # Extract information from the event
    processing_result = event['processing_successful']
    message = event['message']
    email_subject = "File Processing Status"
    email_body = f"The file was processed with the following result: {message}"

    # Send email
    response = ses_client.send_email(
        Source="shsheikhbd@gmail.com",
        Destination={
            "ToAddresses": ["shsheikhbd@gmail.com"]
        },
        Message={
            "Subject": {
                "Data": email_subject
            },
            "Body": {
                "Text": {
                    "Data": email_body
                }
            }
        }
    )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "email_status": "Sent"
        })
    }
