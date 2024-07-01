import yara


def check_yara_packages(repo_file):
    """
    Checks the YARA packages for errors.
    """
    try:
        # Check for errors
        yara.compile(filepath=repo_file["file_path"])
    except Exception as e:
        return False
    return True
