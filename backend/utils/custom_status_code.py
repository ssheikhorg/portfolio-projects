from http.client import responses as http_responses

from fastapi.responses import JSONResponse

# Create a copy of the standard HTTP status codes
HTTP_STATUS_CODES = http_responses.copy()

# Add our custom status code
HTTP_STATUS_CODES[700] = "Custom Error"


# Create a custom JSONResponse class that uses our extended status codes
class CustomJSONResponse(JSONResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.status_code_text = HTTP_STATUS_CODES.get(
            self.status_code, "Unknown Status"
        )


# Patch FastAPI's JSONResponse
from fastapi import responses

responses.JSONResponse = CustomJSONResponse
