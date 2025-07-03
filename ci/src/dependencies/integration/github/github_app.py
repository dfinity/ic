import logging
import os
import re
import time
import typing

import jwt
import requests
from model.repository import Repository

GITHUB_APP_CREDENTIALS = {
    "dfinity": (os.environ.get("GITHUB_APP_CLIENT_ID_DFINITY"), os.environ.get("GITHUB_APP_SIGNING_KEY_DFINITY")),
    "utopia-icp": (os.environ.get("GITHUB_APP_CLIENT_ID_UTOPIA"), os.environ.get("GITHUB_APP_SIGNING_KEY_UTOPIA")),
}

if GITHUB_APP_CREDENTIALS["dfinity"][0] is None or GITHUB_APP_CREDENTIALS["dfinity"][1] is None:
    logging.warning("GITHUB_APP_CREDENTIALS for dfinity are not set, can not clone private repos")


class GithubApp:
    def __init__(self, repos: typing.List[Repository]):
        self.install_token_by_repo_url: typing.Dict[str, typing.Optional[str]] = {}
        for repo in repos:
            if repo.is_private and repo.url.lower().startswith("https://github.com"):
                self.install_token_by_repo_url[repo.url] = None
        if len(self.install_token_by_repo_url) > 0:
            self.__fetch_install_tokens()

    @staticmethod
    def __gen_jwt(owner: str) -> str:
        owner = owner.lower()
        if GITHUB_APP_CREDENTIALS[owner][0] is None or GITHUB_APP_CREDENTIALS[owner][1] is None:
            raise RuntimeError(f"GITHUB_APP_CREDENTIALS environment variable is not set for {owner}")

        # see https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app#example-using-python-to-generate-a-jwt
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 540,
            "iss": GITHUB_APP_CREDENTIALS[owner][0],
        }
        return jwt.encode(payload, GITHUB_APP_CREDENTIALS[owner][1], algorithm="RS256")

    @staticmethod
    def __get_installation_id_by_repo(encoded_jwt: str, owner: str, name: str):
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{name}/installation",
            headers={"Authorization": f"Bearer {encoded_jwt}"},
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Failed to get installation id for repo {owner}/{name}, received status code: {resp.status_code}"
            )
        installation = resp.json()
        return installation["id"]

    @staticmethod
    def __get_install_token(encoded_jwt: str, install_id: str) -> str:
        resp = requests.post(
            f"https://api.github.com/app/installations/{install_id}/access_tokens",
            headers={"Authorization": f"Bearer {encoded_jwt}"},
        )
        if resp.status_code != 201:
            raise RuntimeError(f"Failed to get installation token, received status code: {resp.status_code}")
        token_data = resp.json()
        return token_data["token"]

    def __fetch_install_tokens(self):
        encoded_jwt_by_owner = {}
        token_by_install_id = {}
        for repo_url in self.install_token_by_repo_url.keys():
            match = re.search("^https://github\\.com/(?P<owner>[^/]+)/(?P<name>[^/]+)", repo_url, re.IGNORECASE)
            if match:
                owner = match.group("owner").lower()
                name = match.group("name").lower()
                if owner not in encoded_jwt_by_owner:
                    encoded_jwt_by_owner[owner] = self.__gen_jwt(owner)
                install_id = self.__get_installation_id_by_repo(encoded_jwt_by_owner[owner], owner, name)
                if install_id in token_by_install_id:
                    install_token = token_by_install_id[install_id]
                else:
                    install_token = self.__get_install_token(encoded_jwt_by_owner[owner], install_id)
                    token_by_install_id[install_id] = install_token
                self.install_token_by_repo_url[repo_url] = install_token
            else:
                raise RuntimeError(f"Could not extract owner and repo name from repo url {repo_url}")

    def get_checkout_url(self, url: str) -> str:
        if url in self.install_token_by_repo_url:
            return f'https://x-access-token:{self.install_token_by_repo_url[url]}@{url.lower().replace("https://","")}'
        return url.lower()
