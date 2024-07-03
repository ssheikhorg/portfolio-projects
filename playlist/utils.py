import re

from PyQt5.QtWidgets import QMessageBox


def validate_name(name):
    return bool(name) and len(name) <= 40 and re.match(r"^[\w\s\-]+$", name)


def validate_time(start_time):
    return bool(re.match(r"^[0-2]\d:[0-5]\d$", start_time))


def validate_days(days):
    return bool(re.match(r"^[0-6](,[0-6]){0,6}$", days))


def show_error_message(title, message):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.exec_()
