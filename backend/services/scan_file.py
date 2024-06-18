from config import settings
from fastapi import UploadFile
from utils.miscellaneous import Command, create_tmp_file

import yara


async def clamav_scan(file_to_scan: UploadFile):
    file_bytes = await file_to_scan.read()
    file_extension = file_to_scan.filename.split(".")[-1].lower()
    file_path = create_tmp_file(file_bytes, f"file_to_scan.{file_extension}")
    return scan_with_clamav(file_path)


def scan_with_clamav(temp_file):
    cmd_template = "clamdscan -f {file_path} --config-file={config_file_path}"
    cmd = Command(cmd_template)
    exit_code, resp = cmd(
        file_path=temp_file, config_file_path=settings.clamav_config_file_path
    )
    return resp


async def yara_scan(file_to_scan: UploadFile):
    rules = yara.compile(filepath=settings.yara_rule_packages)
    file_bytes = await file_to_scan.read()
    file_extension = file_to_scan.filename.split(".")[-1].lower()
    file_path = create_tmp_file(file_bytes, f"file_to_scan.{file_extension}")
    return scan_with_yara(file_path, rules)


def scan_with_yara(file_path, rules):
    try:
        matches = rules.match(file_path)
        for match in matches:
            print(
                f"Matched rule '{match.rule}' at offset {match.offset} in file '{file_path}'"
            )
    except yara.Error as e:
        print(f"YARA error while scanning file '{file_path}': {e}")