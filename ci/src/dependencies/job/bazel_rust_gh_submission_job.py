import logging
import os

from integration.github.github_api import GithubApi
from model.log_level import get_log_level

LOCKFILE = "Cargo.Bazel.toml.lock"

if __name__ == "__main__":
    logging.basicConfig(level=get_log_level())

    if "GITHUB_PR_SHA" in os.environ:
        path_to_lockfile = os.path.join(os.environ["GITHUB_PR_SHA"], LOCKFILE)
    else:
        path_to_lockfile = LOCKFILE
    GithubApi.submit_dependencies([path_to_lockfile])
