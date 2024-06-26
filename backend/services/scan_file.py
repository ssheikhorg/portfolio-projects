import os

import yara
from config import settings
from fastapi import UploadFile
from utils.miscellaneous import Command, save_file


def clamav_scan(file_bytes: bytes, file_extension: str):
    try:
        file_path = save_file(file_bytes, f"file_to_scan.{file_extension}")
        return scan_with_clamav(file_path)
    except Exception as e:
        print("The didn't complete without errors: %s", e)
        return False


def scan_with_clamav(temp_file):
    # make sure to chown of /var/lib/docker/data/clamav to 100:101 on host machine
    cmd_template = "clamdscan {file_path}"
    cmd = Command(cmd_template)
    exit_code, resp = cmd(file_path=temp_file)
    return resp


def yara_scan(file_bytes: bytes, file_extension: str):
    try:
        rules = yara.compile(filepath=settings.yara_rule_packages)
        file_path = save_file(file_bytes, f"file_to_scan.{file_extension}")
        return scan_with_yara(file_path, rules)
    except Exception as e:
        print("The rule set didn't compile without errors: %s", e)
        return False


def mycallback(data):
    if data["matches"]:
        print(f"Matched rule '{data['rule']}' in namespace '{data['namespace']}'")
        print(f"Tags: {data['tags']}")
        print(f"Meta: {data['meta']}")
        print("Strings:")
        for string_match in data["strings"]:
            # Access the identifier and whether the match is XORed
            identifier = string_match.identifier
            is_xor = string_match.is_xor
            print(f" - Identifier: {identifier}, XOR: {is_xor}")

            # Print instances of the match
            # for instance in string_match.instances:
            #     print(
            #         f"   - Matched String: {instance.matched_data}, Offset: {instance.offset}"
            #     )

    return yara.CALLBACK_CONTINUE


def scan_with_yara(file_path, rules):
    try:
        matches = rules.match(
            file_path, callback=mycallback, which_callbacks=yara.CALLBACK_MATCHES
        )
        if not matches:
            print(f"No matches found for file '{file_path}'")
    except yara.Error as e:
        print(f"YARA error while scanning file '{file_path}': {e}")
