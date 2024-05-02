import logging
import inspect

# Initialize logging
logging.basicConfig(level=logging.INFO)

def logs(level, message, detail=None):
    """
    Log a message with a specific level and detail.
    """
    # Get the name of the function that called the log function
    function_name = inspect.currentframe().f_back.f_code.co_name

    if level == 'info':
        logging.info(f"{function_name}: {message}. Detail: {detail}")
    elif level == 'warning':
        logging.warning(f"{function_name}: {message}. Detail: {detail}")
    elif level == 'critical':
        logging.critical(f"{function_name}: {message}. Detail: {detail}")
    else:
        logging.debug(f"{function_name}: {message}. Detail: {detail}")
