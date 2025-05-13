"""
import os
import time

from dotenv import load_dotenv, find_dotenv

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions

load_dotenv(find_dotenv())


def aws_login() -> None:
    # Set up the webdriver
    service = Service(executable_path=os.getenv("FIREFOX_DRIVER"))
    driver = webdriver.Firefox(service=service)
    driver.get("https://aws.amazon.com/console/")

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
        expected_conditions.element_to_be_clickable((By.XPATH, '//span[text()="Next"]'))
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
        username_input.send_keys(os.getenv("AWS_USERNAME"))

        # Enter password
        password_input = WebDriverWait(driver, 20).until(
            expected_conditions.presence_of_element_located(
                (By.XPATH, '//input[@id="password"]')
            )
        )
        password_input.clear()
        password_input.send_keys(os.getenv("AWS_PASSWORD"))

        # Click on "Sign in"
        sign_in_button = WebDriverWait(driver, 60).until(
            expected_conditions.element_to_be_clickable(
                (By.XPATH, '//a[@id="signin_button"]')
            )
        )
        sign_in_button.click()
        print("Successfully logged in.")
        time.sleep(50)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Closing the browser.")
        driver.quit()


if __name__ == "__main__":
    aws_login()
"""
