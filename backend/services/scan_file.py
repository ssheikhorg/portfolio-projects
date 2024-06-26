from typing import List, Union

import yara
from config import settings
from schema.data_schema import YaraMatchDetails
from utils.log_function import logs
from utils.miscellaneous import Command, save_file


def clamav_scan(file_bytes: bytes, file_extension: str):
    """
    Perform a ClamAV scan on the provided file.

    Args:
        file_bytes (bytes): Bytes of the file to scan.
        file_extension (str): Extension of the file.

    Returns:
        tuple: Tuple containing exit code, response, and error message.
    """
    try:
        file_path = save_file(file_bytes, f"file_to_scan.{file_extension}")
        scan_res = scan_with_clamav(file_path)
        return scan_res
    except Exception as e:
        logs("error", f"ClamAV scan failed: {str(e)}")  # Log ClamAV scan failure
        return False


def scan_with_clamav(temp_file):
    """
    Perform ClamAV scan using clamdscan.

    Args:
        temp_file (str): Temporary file path for scanning.

    Returns:
        tuple: Tuple containing exit code, response, and error message.
    """
    cmd_template = "clamdscan {file_path}"
    cmd = Command(cmd_template)
    exit_code, resp, error = cmd(file_path=temp_file)
    return exit_code, resp, error


def yara_scan(
    file_bytes: bytes, file_extension: str
) -> Union[List[YaraMatchDetails], bool]:
    """
    Perform YARA scan on the provided file.

    Args:
        file_bytes (bytes): Bytes of the file to scan.
        file_extension (str): Extension of the file.

    Returns:
        Union[List[YaraMatchDetails], bool]: List of YARA match details or False if failed.
    """
    try:
        rules = yara.compile(filepath=settings.yara_rule_packages)
        file_path = save_file(file_bytes, f"file_to_scan.{file_extension}")
        scan_res = scan_with_yara(file_path, rules)
        return scan_res
    except Exception as e:
        logs("error", f"YARA scan failed: {str(e)}")  # Log YARA scan failure
        return False


def mycallback(data):
    """
    Callback function for YARA matches.

    Args:
        data (dict): Data containing information about YARA match.

    Returns:
        int: YARA callback status.
    """
    match_detail = {
        "rule": data["rule"],
        "namespace": data["namespace"],
        "tags": data["tags"],
        "meta": data["meta"],
        "strings": [
            {
                "identifier": string_match.identifier,
                "is_xor": string_match.is_xor,
                # Include more details if needed
            }
            for string_match in data["strings"]
        ],
    }
    logs("info", f"Match detail for YARA scan: {match_detail}")
    return yara.CALLBACK_CONTINUE


def scan_with_yara(file_path, rules):
    """
    Perform YARA scan using compiled rules.

    Args:
        file_path (str): Path of the file to scan.
        rules (yara.Rules): Compiled YARA rules.

    Returns:
        Union[str, List[YaraMatchDetails]]: "OK" if no matches found, otherwise list of YARA match details.
    """
    matches = rules.match(
        file_path, callback=mycallback, which_callbacks=yara.CALLBACK_MATCHES
    )
    if not matches:
        return "OK"
    return matches
