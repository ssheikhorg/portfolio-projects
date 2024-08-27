def handler(event, _) -> dict:
    print("Process Event: ", event)
    is_valid = event.get("valid", False)

    return {"statusCode": 200 if is_valid else 400, "valid": is_valid}
