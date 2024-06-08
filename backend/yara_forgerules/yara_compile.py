import logging

import yara


def check_yara_packages(repo_files):
    """
    Checks the YARA packages for errors.
    """
    # Loop over the list and print the file names
    for repo_file in repo_files:
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


def get_yara_qa_commit_hash():
    """
    Returns the current commit hash of the lst commit of the YARA QA sub repository.
    """
    # Get the current commit hash of the YARA QA sub repository
    try:
        with open(".git/modules/qa/yaraQA/refs/heads/main", "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        logging.warning("Couldn't get the commit hash of the YARA QA repository: %s", e)
        return "unknown"
