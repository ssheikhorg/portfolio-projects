import os
import shlex
import subprocess
import tempfile
import uuid


def create_tmp_file(bytes, filename) -> str:
    dir = tempfile.mkdtemp()
    file_path = os.path.join(dir, filename)
    with open(file_path, "wb") as f:
        f.write(bytes)
    return file_path


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
        except subprocess.CalledProcessError as e:
            output = e.stderr
            returncode = e.returncode
        output = output.decode("utf-8")
        return returncode, output


def generate_file_id():
    return str(uuid.uuid4())
