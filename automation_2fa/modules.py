import os
import time
from dotenv import load_dotenv, find_dotenv

import pyotp
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions

load_dotenv(find_dotenv())


class AwsMfa:
    def __init__(self) -> None:
        self.driver = os.getenv("FIREFOX_DRIVER")
        self.url = "https://aws.amazon.com/console/"
        self.secret = os.getenv("AWS_SECRET")
        self.password = os.getenv("AWS_PASSWORD")
        self.username = os.getenv("AWS_USERNAME")

    def get_token(self) -> str:
        totp = pyotp.TOTP(self.secret)
        return totp.now()

    def login(self) -> None:
        # Set up the webdriver
        service = Service(executable_path=self.driver)
        driver = webdriver.Firefox(service=service)
        driver.get(self.url)

        # Click on "Sign In"
        sign_in_button = driver.find_element(By.LINK_TEXT, "Sign In")
        sign_in_button.click()

        # select IAM user
        iam_user_button = driver.find_element(By.XPATH, "//label[text()='IAM user']")
        iam_user_button.click()

        # Enter Account ID
        account_id_input = WebDriverWait(driver, 10).until(
            expected_conditions.presence_of_element_located(
                (By.XPATH, '//input[@id="resolving_input"]')
            )
        )
        account_id_input.clear()
        account_id_input.send_keys(os.getenv("AWS_ACCOUNT"))

        # Click on "Next"
        next_button = WebDriverWait(driver, 10).until(
            expected_conditions.element_to_be_clickable(
                (By.XPATH, '//span[text()="Next"]')
            )
        )
        next_button.click()

        try:
            # IAM user name
            username_input = WebDriverWait(driver, 20).until(
                expected_conditions.presence_of_element_located(
                    (By.XPATH, '//input[@id="username"]')
                )
            )
            username_input.clear()
            username_input.send_keys(self.username)

            # Enter password
            password_input = WebDriverWait(driver, 20).until(
                expected_conditions.presence_of_element_located(
                    (By.XPATH, '//input[@id="password"]')
                )
            )
            password_input.clear()
            password_input.send_keys(self.password)

            # Click on "Sign in"
            sign_in_button = WebDriverWait(driver, 60).until(
                expected_conditions.element_to_be_clickable(
                    (By.XPATH, '//a[@id="signin_button"]')
                )
            )
            sign_in_button.click()

            # Enter MFA token
            token_input = WebDriverWait(driver, 10).until(
                expected_conditions.presence_of_element_located(
                    (By.XPATH, '//input[@id="mfacode"]')
                )
            )
            token_input.clear()
            token_input.send_keys(self.get_token())

            # Click on "Submit"
            submit_button = WebDriverWait(driver, 10).until(
                expected_conditions.element_to_be_clickable(
                    (By.XPATH, '//a[@id="submitMfa_button"]')
                )
            )
            submit_button.click()
            print("Successfully logged in.")
            time.sleep(50)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("Closing the browser.")
            driver.quit()


if __name__ == "__main__":
    mfa = AwsMfa()
    mfa.login()
