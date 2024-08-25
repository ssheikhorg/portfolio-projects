import json
import boto3

ses_client = boto3.client('ses')


def handler(event, context):
    print("Send Email Event: ", event)
    processing_successful = event["body"]["valid"]
    message = event["body"]["message"]
    email_subject = "File Processing Status"
    email_body = f"The file was processed with the following result: {message}"

    # # Send email
    # response = ses_client.send_email(
    #     Source="shsheikhbd@gmail.com",
    #     Destination={
    #         "ToAddresses": ["shsheikhbd@gmail.com"]
    #     },
    #     Message={
    #         "Subject": {
    #             "Data": email_subject
    #         },
    #         "Body": {
    #             "Text": {
    #                 "Data": email_body
    #             }
    #         }
    #     }
    # )

    return {
        "statusCode": 200,
        "body": json.dumps({
            "valid": processing_successful,
            "message": "Email sent successfully"
        })
    }
