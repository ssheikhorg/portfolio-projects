import os
from typing import List, Tuple, Union

import yara

from api.process_file.processor import create_tmp_file, Command
from config import settings
from fastapi import HTTPException
from schema.data_schema import YaraMatchDetails


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
    try:

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
