from time import time
from urllib import response
from urllib.request import urlopen

import requests
from src.core.config import settings
from src.utils.miscellanous import Dict2Obj, extract_git_archive


class Github:
    base_url = "https://api.github.com"
    project = None

    def __init__(self, repo_namespace: str = None):
        self.token = settings.github_token
        self.headers = {
            "Authorization": f"token {self.token}",
        }
        if repo_namespace:
            self.repo_namespace = repo_namespace
            proj = self.get_project(self.repo_namespace)
            self.project = Dict2Obj(proj)

    def get_project(self, repo_namespace: str):
        response = requests.get(
            f"{self.base_url}/repos/{repo_namespace}", headers=self.headers
        )
        resp = response.json()
        return resp

    def get_project_archive(
        self, repo_namespace: str = None, ref: str = None, dir: str = None
    ):
        if not self.project:
            assert repo_namespace
            self.repo_namespace = repo_namespace
            self.project = self.get_project(repo_namespace)
        ref = ref or self.project.default_branch
        with requests.get(
            f"{self.base_url}/repos/{self.repo_namespace}/zipball/{ref}",
            stream=True,
            headers=self.headers,
        ) as r:
            r.raise_for_status()
            if dir:
                zipfn = f"{dir}/archive.zip"
                with open(zipfn, "wb") as fd:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            fd.write(chunk)
                extract_git_archive(zipfn, dir)
                # subprocess.run(["unzip", "-bo", zipfn])
                # os.unlink(zipfn)
                return dir
            else:
                return r

    def get_project_tree(
        self,
        repo_namespace: str = None,
        ref: str = None,
        recursive: bool = True,
        path: str = None,
    ):
        if not self.project:
            assert repo_namespace
            self.repo_namespace = repo_namespace
            self.project = self.get_project(repo_namespace)
        ref = ref or self.project["default_branch"]
        url = "{}/repos/{}/git/trees/{}?{}=".format(
            self.base_url,
            self.repo_namespace,
            ref,
            f"recursive={recursive}" if recursive else "",
        )
        files_response = requests.get(url, headers=self.headers)
        files_list = files_response.json()
        if isinstance(files_list, dict) and files_list.get("tree"):
            files_list = list(
                map(
                    lambda file: {
                        **file,
                        "id": file["sha"],
                        "name": file["path"].split("/").pop(),
                    },
                    files_list["tree"],
                )
            )
        elif isinstance(files_list, dict):
            files_list = [files_list]
        if path:
            files_list = list(filter(lambda d: d["path"].startswith(path), files_list))
        return files_list

    def get_project_file(
        self, repo_namespace: str = None, file_path: str = None, ref: str = None
    ):
        if not self.project:
            assert repo_namespace
            self.repo_namespace = repo_namespace
            self.project = self.get_project(repo_namespace)
        resp = requests.get(
            f"{self.base_url}/repos/{self.repo_namespace}/contents/{file_path}?ref={ref}",
            headers=self.headers,
        )
        file_resp = resp.json()
        # print(file_resp)
        # return file_resp
        if not file_resp:
            return None
        data = urlopen(file_resp["download_url"]).read().decode()
        return data

    def get_id(self):
        return self.project["id"]

    def list_commits(self):
        repo_namespace = self.repo_namespace
        req = requests.get(
            f"{self.base_url}/repos/{repo_namespace}/commits", headers=self.headers
        )
        resp = req.json()
        return resp

    def list_branches(self, full=True):
        repo_namespace = self.repo_namespace
        req = requests.get(
            f"{self.base_url}/repos/{repo_namespace}/branches", headers=self.headers
        )
        resp = req.json()
        branches = []
        if full:
            for r in resp:
                id = r["commit"]["sha"]
                commit = self.get_commit(id)
                commit["id"] = commit.pop("sha")
                commit["author"] = dict(
                    list(commit["author"].items())
                    + list(commit["commit"]["author"].items())
                )
                commit["message"] = commit["commit"]["message"]
                commit["created_at"] = commit["commit"]["committer"]["date"]
                branches.append(
                    {
                        "name": r["name"],
                        "protected": r["protected"],
                        "commit": commit,
                    }
                )
        else:
            branches = resp
        return branches

    def list_members(self):
        repo_namespace = self.repo_namespace
        req = requests.get(
            f"{self.base_url}/repos/{repo_namespace}/contributors", headers=self.headers
        )
        resp = req.json()
        members_list = []
        for m in resp:
            # print(m['url'])
            # user = requests.get(m['url']).json() ## timesout
            user = m
            # print(user)
            members_list.append(
                {
                    "name": user["login"],
                    "email": user["html_url"],
                    "avatar": user["avatar_url"],
                }
            )
        print("members_list-len", len(members_list))
        return members_list

    def get_user(self, url):
        req = requests.get(url, headers=self.headers)
        resp = req.json()
        # print('github.get_user() =>', resp)
        user = Dict2Obj(resp)
        author = {
            "id": user.id,
            "name": user.name or user.login,
            "email": user.email,
            "avatar_url": user.avatar_url,
            "type": user.type,
            "bio": user.bio,
            "link": user.blog,
        }
        return author

    def get_commit(self, id):
        namespace = self.repo_namespace
        req = requests.get(
            f"{self.base_url}/repos/{namespace}/commits/{id}", headers=self.headers
        )
        resp = req.json()
        return resp
