import os
from datetime import datetime

import cv2
import numpy as np
from utils.miscellaneous import create_tmp_file


def file_rename(file_data, file_name: str, is_ndarray: bool):
    date_prefix = datetime.now().strftime("%y%m%d")
    new_filename = f"{date_prefix}_{file_name}"

    if isinstance(file_data, str) and os.path.isfile(file_data):
        # If file_data is a file path
        new_file_path = os.path.join(os.path.dirname(file_data), new_filename)
        os.rename(file_data, new_file_path)
        return new_file_path
    elif is_ndarray:
        # If it's an np.ndarray, convert it to bytes
        _, buffer = cv2.imencode(".png", file_data)
        file_bytes = buffer.tobytes()
    else:
        # Assume it's already in bytes
        file_bytes = file_data

    temp_file_path = create_tmp_file(file_bytes, new_filename)
    return temp_file_path
