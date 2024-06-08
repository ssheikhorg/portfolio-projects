import os
import shlex
import subprocess
from zipfile import ZipFile


def extract_git_archive(zip_file, dir):
    with ZipFile(zip_file, "r") as zipObj:
        listOfFileNames = zipObj.namelist()
        print("listOfFileNames", listOfFileNames)
        top_folder = listOfFileNames[0]
        root_folder = f"{dir}/{top_folder}"
        print(top_folder, root_folder)
        zipObj.extractall(dir)
        # mv_cmd = f'cp -vaR {top_folder}. . && rmdir {root_folder}'
        cp_cmd = f"cp -r {top_folder}* . && rm -R {top_folder}"
        ## https://stackoverflow.com/a/21804962/1226748 ,
        ## https://unix.stackexchange.com/q/19344
        subprocess.call(cp_cmd, cwd=f"{dir}/", shell=True)
        # os.rmdir(root_folder)
    os.unlink(zip_file)
    return dir


class Command(object):
    def __init__(
        self,
        cmd_template=None,
    ):
        """Command base class for MinIO mc."""
        self.cmd_template = cmd_template
        self.flags = ""  ## '--JSON on' #{'json': True}

    def __call__(self, **kwargs):
        kwargs.setdefault("flags", self.flags)
        self.command_string = self.cmd_template.format(**kwargs)
        print(self.command_string)
        try:
            _output = subprocess.run(
                shlex.split(self.command_string), capture_output=True
            )
            returncode = _output.returncode
            output = _output.stdout
        except subprocess.CalledProcessError as e:
            # print(e)
            output = e.stderr
            returncode = e.returncode
        # else:
        #    output = _output
        output = output.decode("utf-8")
        # print('output => ', output)
        # self.result = json.loads(output)
        return returncode, output


class Dict2Obj(object):
    """
    Turns a dictionary into a class
    """

    def __init__(self, dictionary):
        for key in dictionary:
            setattr(self, key, dictionary[key])
