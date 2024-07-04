from datetime import datetime

from utils.miscellaneous import create_tmp_file


def file_rename(file_bytes: bytes, file_name: str):
    date_prefix = datetime.now().strftime("%y%m%d")
    original_filename = file_name
    new_filename = f"{date_prefix}_{original_filename}"
    temp_file_path = create_tmp_file(file_bytes, new_filename)
    return temp_file_path
