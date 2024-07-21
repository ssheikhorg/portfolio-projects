import os
import shlex
import subprocess
import tempfile
import uuid
from io import BytesIO

import magic
from config import settings
from PIL import Image


def is_image(file_bytes: bytes) -> bool:
    try:
        image = Image.open(BytesIO(file_bytes))
        image.verify()  # Verify that it is an image
        return True
    except (IOError, SyntaxError):
        return False


def save_file(file_bytes, file_name):
    file_path = os.path.join(settings.clamav_scanned_dir, file_name)
    with open(file_path, "wb") as f:
        f.write(file_bytes)
    return file_path


def create_tmp_file(bytes, filename) -> str:
    dir = tempfile.mkdtemp()
    file_path = os.path.join(dir, filename)
    with open(file_path, "wb") as f:
        f.write(bytes)
    return file_path


def get_mime_type(file: BytesIO):
    """
    Determines MIME type of file based on its content using magic
    """
    file.seek(0)
    mime_type = magic.from_buffer(file.read(2048), mime=True).decode("utf-8")
    file.seek(0)
    return mime_type


class Command(object):
    def __init__(
        self,
        cmd_template=None,
    ):
        """Command base class for MinIO mc."""
        self.cmd_template = cmd_template

    def __call__(self, **kwargs):
        self.command_string = self.cmd_template.format(**kwargs)
        print(self.command_string)
        try:
            _output = subprocess.run(
                shlex.split(self.command_string), capture_output=True
            )
            returncode = _output.returncode
            output = _output.stdout
            error = _output.stderr
        except subprocess.CalledProcessError as e:
            output = e.stderr
            returncode = e.returncode
        output = self.decode_output(output)
        error = self.decode_output(error)
        return returncode, output, error

    def decode_output(self, output):
        try:
            return output.decode("utf-8")
        except UnicodeDecodeError:
            return output.decode("latin-1")


def generate_file_id():
    return str(uuid.uuid4())
