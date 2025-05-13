import requests
from os import getenv

from dotenv import load_dotenv

load_dotenv()


def verify_token_permissions():
    token = getenv("FB_ACCESS_TOKEN")
    response = requests.get(
        f"https://graph.facebook.com/v19.0/me/permissions?access_token={token}"
    )
    if response.status_code == 200:
        print("Current permissions:")
        for perm in response.json()["data"]:
            print(f"{perm['permission']}: {perm['status']}")
    else:
        print("Error checking permissions:", response.json())


verify_token_permissions()
