from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver import ActionChains
import time


def automation():
    driver = webdriver.Edge()
    url = "https://www.barnesandnoble.com/h/books/browse"
    driver.get(url)

    acc_path = "/html/body/div[1]/header/nav/div/div[2]/ul[2]/li[1]"
    account = driver.find_element(By.XPATH, acc_path)
    log_path = "/html[1]/body[1]/div[1]/header[1]/nav[1]/div[1]/div[2]/ul[2]/li[1]/div[1]/dd[1]/a[1]"
    login = driver.find_element(By.XPATH, log_path)
    forget = driver.find_element(By.XPATH, "//*[@id='loginForgotPassword']")
    email = driver.find_element(By.XPATH, "//input[@id='email']")

    actions = ActionChains(driver)
    actions.move_to_element(account).perform()
    time.sleep(5)
    login.click()
    time.sleep(10)
    forget.click()
    time.sleep(4)
    email.send_keys("shsheikhbd@gmail.com")


if __name__ == "__main__":
    automation()
