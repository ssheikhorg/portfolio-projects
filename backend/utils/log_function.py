import logging

def setup_logging(loglevel: str):
    loglevel_mapping = {
        "Debug": logging.DEBUG,
        "Info": logging.INFO,
        "Warning": logging.WARNING,
        "Error": logging.ERROR,
        "Critical": logging.CRITICAL,
    }
    logging.basicConfig(level=loglevel_mapping.get(loglevel, logging.INFO),
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def logs(level: str, message: str):
    logger = logging.getLogger(__name__)
    log_function = getattr(logger, level.lower(), logger.info)
    log_function(message)
