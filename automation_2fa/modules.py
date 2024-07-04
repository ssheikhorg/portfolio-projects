from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import pyotp
import urllib.parse

# Configuration settings
AWS_LOGIN_URL = "http://127.0.0.1:8000/"
DUO_URL = f"otpauth://totp/Duo:testuser?secret=JBSWY3DPEHPK3PXP&issuer=Duo"
webdriver_path = "path/to/chromedriver"

# Credentials
USERNAME = "ssheikh"
PASSWORD = "password"


def extract_secret_key_from_url(url):
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    secret_key = query_params.get("secret", [None])[0]
    return secret_key


def generate_otp(secret_key):
    totp = pyotp.TOTP(secret_key)
    return totp.now()


def automate_login():
    # Extract secret key
    secret_key = extract_secret_key_from_url(DUO_URL)

    # Initialize WebDriver
    driver = webdriver.Chrome(executable_path=webdriver_path)
    driver.get(AWS_LOGIN_URL)

    try:
        # Wait for the username field and enter username
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.NAME, "username"))
        ).send_keys(USERNAME)

        # Enter password
        driver.find_element(By.NAME, "password").send_keys(PASSWORD)

        # Generate OTP
        otp = generate_otp(secret_key)

        # Enter OTP
        driver.find_element(By.NAME, "otp").send_keys(otp)

        # Submit the form
        driver.find_element(By.NAME, "submit").click()

        # Wait for login to complete
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.ID, "logged_in_element"))
        )

        print("Login successful!")
    finally:
        # Close the WebDriver
        driver.quit()
