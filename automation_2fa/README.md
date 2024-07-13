# AWS 2FA Login Automation

This Python script automates the login process to the AWS Management Console using Selenium WebDriver with Firefox, specifically designed to handle Two-Factor Authentication (2FA).

## Features

- Automates AWS Console login with IAM credentials.
- Supports Two-Factor Authentication (2FA) token entry.
- Utilizes environment variables for secure credential management.

## Prerequisites

- Python 3.x installed on your system.
- Selenium library for Python.
- Firefox and its WebDriver (geckodriver).
- A valid AWS account with IAM user credentials and 2FA enabled.

## Environment Variables

Before running the script, set the following environment variables for security:

- `FIREFOX_DRIVER`: Full path to the Firefox WebDriver (geckodriver) executable.
- `AWS_ACCOUNT`: Your AWS account ID.
- `AWS_USERNAME`: Your AWS IAM username.
- `AWS_PASSWORD`: Your AWS IAM password.
- `AWS_SECRET`: Your 2FA secret key for generating tokens.

## Installation

1. **Install Selenium:**

   ```sh
   pip install selenium pyotp
   