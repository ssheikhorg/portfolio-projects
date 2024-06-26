from typing import List, Union

import yara
from config import settings
from schema.data_schema import YaraMatchDetails
from utils.log_function import logs
from utils.miscellaneous import Command, save_file


def clamav_scan(file_bytes: bytes, file_extension: str):
    try:
        file_path = save_file(file_bytes, f"file_to_scan.{file_extension}")
        scan_res = scan_with_clamav(file_path)
        return scan_res
    except Exception as e:
        print("The didn't complete without errors: %s", e)
        return False


def scan_with_clamav(temp_file):
    # make sure to chown of /var/lib/docker/data/clamav to 100:101 on host machine
    cmd_template = "clamdscan {file_path}"
    cmd = Command(cmd_template)
    exit_code, resp, error = cmd(file_path=temp_file)
    return exit_code, resp, error


def yara_scan(
    file_bytes: bytes, file_extension: str
) -> Union[List[YaraMatchDetails], bool]:
    try:
        rules = yara.compile(filepath=settings.yara_rule_packages)
        file_path = save_file(file_bytes, f"file_to_scan.{file_extension}")
        scan_res = scan_with_yara(file_path, rules)
        return scan_res
    except Exception as e:
        print("The rule set didn't compile without errors: %s", e)
        return False


def mycallback(data):
    if data["matches"]:
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
        logs("info", f"match detail for yara_scan {str(match_detail)}")
    return yara.CALLBACK_CONTINUE


def scan_with_yara(file_path, rules):
    matches = rules.match(
        file_path, callback=mycallback, which_callbacks=yara.CALLBACK_MATCHES
    )
    if not matches:
        return "OK"
    return matches
