import asyncio
import base64
import hmac
import hashlib
import time
from httpx import AsyncClient, BasicAuth


def generate_totp_password(userid: str, shared_secret: str) -> str:
    current_time = int(time.time())
    time_step = 30  # TOTP's Time Step X is 30 seconds
    t0 = 0  # T0 is 0
    counter = current_time // time_step - t0
    totp_password = hmac.new(
        key=shared_secret.encode(),
        msg=counter.to_bytes(8, byteorder='big'),
        digestmod=hashlib.sha512
    ).hexdigest()[-10:]
    return totp_password


def generate_authorization_header(userid: str, password: str) -> str:
    credentials = f"{userid}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    authorization_header = f"Basic {encoded_credentials}"
    return authorization_header


async def send_request() -> None:
    user_id = "shsheikhbd@gmail.com"
    shared_secret = user_id + "A@cc0unt^123"
    totp_password = generate_totp_password(user_id, shared_secret)
    authorization_header = generate_authorization_header(user_id, totp_password)
    headers = {
        "Authorization": authorization_header,
        "Content-Type": "application/json"
    }
    payload = {
        "github_url": "https://gist.github.com/ssheikhorg/9364013d4f1c8c3b8240a44cd8f1147f",
        "contact_email": user_id,
        "solution_language": "python"
    }

    async with AsyncClient() as client:
        try:
            url = "https://api.challenge.hennge.com/challenges/003"
            response = await client.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                print(response.json())
            else:
                print(response.status_code)
        except Exception as e:
            print(e)


if __name__ == "__main__":
    asyncio.run(send_request())


'''
import asyncio
import base64
import hashlib
import pyotp
from httpx import AsyncClient, BasicAuth


def generate_totp_password(secret: str) -> str:
    totp = pyotp.TOTP(secret, digits=10)
    return totp.now()

async def send_request() -> dict:
    user_id = "shsheikhbd@gmail.com"
    shared_secret = user_id + "HENNGECHALLENGE003"
    shared_secret_base32 = base64.b32encode(shared_secret.encode()).decode()

    totp = pyotp.TOTP(
        shared_secret_base32,
        interval=30,
        digits=10,
        digest=hashlib.sha512
    )
    totp_password = totp.now()
    auth = BasicAuth(user_id, totp_password)
    headers = {"Content-Type": "application/json"}
    payload = {
        "github_url": "https://gist.github.com/ssheikhorg/9364013d4f1c8c3b8240a44cd8f1147f",
        "contact_email": user_id,
        "solution_language": "python"
    }
    async with AsyncClient() as client:
        try:
            url = "https://api.challenge.hennge.com/challenges/003"
            response = await client.post(url, json=payload, headers=headers, auth=auth)
            if response.status_code == 200:
                return {"message": "Success"}
            return {"error": "Failed"}
        except Exception as e:
            return {"error": str(e)}


if __name__ == "__main__":
    asyncio.run(send_request())

'''