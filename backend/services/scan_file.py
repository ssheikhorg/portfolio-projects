import os
from typing import List, Tuple, Union

import yara

from api.process_file.processor import save_file, create_tmp_file, Command
from config import settings
from fastapi import HTTPException
from schema.data_schema import YaraMatchDetails


def clamav_scan(
    file_bytes: bytes, file_extension: str
) -> Union[Tuple[int, str, str], bool]:
    """
    Perform a ClamAV scan on the provided file.

    Args:
        file_bytes (bytes): Bytes of the file to scan.
        file_extension (str): Extension of the file.

    Returns:
        Union[Tuple[int, str, str], bool]: Tuple containing exit code, response, and error message, or False if failed.
    """
    try:
        file_path = save_file(file_bytes, f"file_to_scan.{file_extension}")
        return scan_with_clamav(file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ClamAV scan failed: {str(e)}")


def scan_with_clamav(temp_file: str) -> Tuple[int, str, str]:
    """
    Perform ClamAV scan using clamdscan.

    Args:
        temp_file (str): Temporary file path for scanning.

    Returns:
        Tuple[int, str, str]: Tuple containing exit code, response, and error message.
    """
    cmd_template = "clamdscan {file_path}"
    cmd = Command(cmd_template)
    exit_code, resp, error = cmd(file_path=temp_file)
    return exit_code, resp, error


def yara_scan(
    file_name: str, file_bytes: bytes, file_extension: str
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
        file_path = create_tmp_file(file_bytes, f"file_to_scan.{file_extension}")
        externals = {
            "filename": file_name,
            "filepath": file_path,
            "extension": file_extension,
            "filetype": "",
            "md5": "",
            "filesize": os.path.getsize(file_path),
            "fullpath": os.path.abspath(file_path),
        }
        rules = yara.compile(filepath=settings.yara_rule_packages, externals=externals)
        return scan_with_yara(file_path, rules)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"YARA scan failed: {str(e)}")


def mycallback(data: dict) -> int:
    """
    Callback function for YARA matches.

    Args:
        data (dict): Data containing information about YARA match.

    Returns:
        int: YARA callback status.
    """
    match_detail = YaraMatchDetails(
        rule=data["rule"],
        namespace=data["namespace"],
        tags=data["tags"],
        meta=data["meta"],
        strings=[
            {
                "identifier": string_match.identifier,
            }
            for string_match in data["strings"]
        ],
    )
    return yara.CALLBACK_CONTINUE


def scan_with_yara(
    file_path: str, rules: yara.Rules
) -> Union[str, List[YaraMatchDetails]]:
    """
    Perform YARA scan using compiled rules.

    Args:
        file_path (str): Path of the file to scan.
        rules (yara.Rules): Compiled YARA rules.

    Returns:
        Union[str, List[YaraMatchDetails]]: "OK" if no matches found, otherwise list of YARA match details.
    """

    matches = rules.match(
        file_path,
        callback=mycallback,
        which_callbacks=yara.CALLBACK_MATCHES,
    )
    if not matches:
        return "OK"
    return matches
