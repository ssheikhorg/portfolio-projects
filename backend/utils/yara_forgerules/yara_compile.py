import logging

import yara


def check_yara_packages(repo_file):
    """
    Checks the YARA packages for errors.
    """
    # Loop over the list and print the file names
    logging.info(
        "Checking YARA package '%s' in file: %s",
        repo_file["name"],
        repo_file["file_path"],
    )
    # Compile the rule set
    try:
        # Check for errors
        yara.compile(filepath=repo_file["file_path"])
    except Exception as e:
        logging.error("The rule set didn't compile without errors: %s", e)
        return False
    return True
