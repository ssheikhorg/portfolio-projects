from selenium import webdriver
from selenium.common import ElementNotInteractableException
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions


def aws_login() -> None:
    ff_driver = "D:\\webdrivers\\geckodriver.exe"
    with open('login_data.txt') as data:
        login_data = [x.strip() for x in data.readlines()]

    # Set up the webdriver
    service = Service(executable_path=ff_driver)
    driver = webdriver.Firefox(service=service)
    driver.get("https://aws.amazon.com/console/")

    try:
        sign_in_button = driver.find_element(By.LINK_TEXT, "Sign In")
        sign_in_button.click()

        # Enter email
        email_input = WebDriverWait(driver, 10).until(
            expected_conditions.presence_of_element_located(
                (By.XPATH, '//input[@id="resolving_input"]')
            )
        )
        email_input.clear()
        email_input.send_keys(login_data[0])

        # Click on "Next"
        next_button = WebDriverWait(driver, 10).until(
            expected_conditions.element_to_be_clickable(
                (By.XPATH, '//span[text()="Next"]')
            )
        )
        next_button.click()

        try:
            # Enter password
            password_input = WebDriverWait(driver, 10).until(
                expected_conditions.presence_of_element_located(
                    (By.XPATH, '//input[@id="password"]')
                )
            )
            password_input.clear()
            password_input.send_keys(login_data[1])
        except ElementNotInteractableException:
            pass

        # Click on "Sign in"
        sign_in_button = WebDriverWait(driver, 10).until(
            expected_conditions.element_to_be_clickable(
                (By.XPATH, '//span[text()="Sign in"]')
            )
        )
        sign_in_button.click()

        # # Security check
        # WebDriverWait(driver, 10).until(
        #     expected_conditions.presence_of_element_located(
        #         (By.XPATH, '//input[@id="password"]')
        #     )
        # )


    except Exception as e:
        print("Error:", e)
    finally:
        driver.quit()
