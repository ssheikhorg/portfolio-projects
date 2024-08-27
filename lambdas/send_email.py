import boto3

ses_client = boto3.client('ses')


def send_email(subject: str, body: str) -> dict:
    source_email = "ssheikhorg@hotmail.com"
    destination_email = "shsheikhbd@gmail.com"
    response = ses_client.send_email(
        Source=source_email,
        Destination={
            "ToAddresses": [destination_email]
        },
        Message={
            "Subject": {
                "Data": subject
            },
            "Body": {
                "Text": {
                    "Data": body
                }
            }
        }
    )
    return response


def handler(event, _) -> dict:
    print("Send Email Event: ", event)
    email_subject = "File Processing Status"

    if "Payload" not in event:
        send_email(email_subject, "The file processing failed.")
        return {
            "statusCode": 400,
            "valid": False
        }
    send_email(email_subject, "The file processing was successful.")

    return {
        "statusCode": 200,
        "valid": True
    }
