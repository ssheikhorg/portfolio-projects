import logging
import sys
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, List

FORMATTER = logging.Formatter("%(asctime)s - %(name)s - %(message)s - %(levelname)s")
LOG_DIR = Path(__file__).resolve().parent.parent / "logs/tmp"
if not LOG_DIR.exists():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def get_console_handler() -> logging.StreamHandler:
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(FORMATTER)
    return console_handler


def get_file_handler(name: str) -> TimedRotatingFileHandler:
    file_handler = TimedRotatingFileHandler(
        LOG_DIR / f"{name}.log", when="midnight", backupCount=7
    )
    file_handler.setFormatter(FORMATTER)
    return file_handler


class InMemoryLogHandler(logging.Handler):
    """Custom log handler that stores logs in a list."""

    def __init__(self):
        super().__init__()
        self.log_storage = []

    def emit(self, record: logging.LogRecord) -> None:
        log_entry = self.format(record)
        self.log_storage.append(log_entry)


def get_in_memory_handler() -> InMemoryLogHandler:
    """Create an in-memory log handler."""
    memory_handler = InMemoryLogHandler()
    memory_handler.setFormatter(FORMATTER)
    return memory_handler


def get_logger(logger_name: str) -> tuple[Any, InMemoryLogHandler]:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(get_console_handler())
    logger.addHandler(get_file_handler(logger_name))

    memory_handler = get_in_memory_handler()
    logger.addHandler(memory_handler)

    logger.propagate = False
    return logger, memory_handler
