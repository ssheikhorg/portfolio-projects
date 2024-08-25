import json


def handler(event, context):
    print("Process Event: ", event)
    is_valid = event["body"]["valid"]

    return {
        "statusCode": 200,
        "body": json.dumps({
            "valid": is_valid,
            "message": "File processed successfully"
        })
    }
