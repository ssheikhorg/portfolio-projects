import json

def handler(event, context):
    # Example: Basic validation
    file_valid = True  # Implement actual validation logic

    return {
        "statusCode": 200,
        "body": json.dumps({
            "valid": file_valid,
            "message": "File is valid" if file_valid else "File is invalid"
        })
    }
