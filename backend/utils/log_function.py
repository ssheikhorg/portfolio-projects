import logging
import sys
from typing import Dict

# Global variables
LOGLEVEL_MAPPING: Dict[str, int] = {
    "Debug": logging.DEBUG,
    "Info": logging.INFO,
    "Warning": logging.WARNING,
    "Error": logging.ERROR,
    "Critical": logging.CRITICAL,
}
CURRENT_LOGLEVEL = logging.INFO


class ExactLevelFilter(logging.Filter):
    def __init__(self, level):
        self.level = level

    def filter(self, record):
        return record.levelno == self.level


def setup_logging():
    # Configure the root logger
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # Allow all levels, we'll filter later

    # Create a formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # Create a stream handler
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    # Add the handler to the root logger
    root.addHandler(stream_handler)


def set_log_level(loglevel: str):
    global CURRENT_LOGLEVEL
    CURRENT_LOGLEVEL = LOGLEVEL_MAPPING.get(loglevel, logging.INFO)

    # Get the root logger
    root = logging.getLogger()

    # Remove all handlers
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    # Create a new handler with the exact level filter
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(CURRENT_LOGLEVEL)
    handler.addFilter(ExactLevelFilter(CURRENT_LOGLEVEL))

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)

    root.addHandler(handler)


def get_logger(name: str = __name__):
    return logging.getLogger(name)


def logs(level: str, message: str, logger_name: str = __name__):
    logger = get_logger(logger_name)
    log_function = getattr(logger, level.lower(), logger.info)
    log_function(message)
