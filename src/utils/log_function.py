import logging
import inspect

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Create a file handler and set its level to INFO
file_handler = logging.FileHandler('logfile.log')
file_handler.setLevel(logging.INFO)

# Create a formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Set the formatter for the file handler
file_handler.setFormatter(formatter)

# Add the file handler to the root logger
logging.getLogger().addHandler(file_handler)

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


# Read and print the contents of the log file
with open('logfile.log', 'r') as file: #for testing
    print("Contents of logfile.log:")
    print(file.read())
