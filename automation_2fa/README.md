# AWS Login Automation

This script automates the login process to the AWS Management Console using Selenium WebDriver with Firefox.

## Prerequisites

- Python 3.x
- Selenium library
- Firefox WebDriver (geckodriver)
- Environment variables for AWS credentials and WebDriver path

## Environment Variables

Set the following environment variables:

- `FIREFOX_DRIVER`: Path to the Firefox WebDriver executable
- `AWS_ACCOUNT`: Your AWS account ID
- `AWS_USERNAME`: Your AWS IAM username
- `AWS_PASSWORD`: Your AWS IAM password

## Installation

1. Install Selenium using pip:

    ```sh
    pip install selenium
    ```

2. Download and install the Firefox WebDriver (geckodriver) from [here](https://github.com/mozilla/geckodriver/releases).

3. Set the required environment variables.

## Usage

Run the script using Python:

```sh
python aws_login.py
