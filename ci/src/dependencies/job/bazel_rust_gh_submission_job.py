import logging
import os

from integration.github.github_api import GithubApi
from model.log_level import get_log_level

LOCKFILE = "Cargo.Bazel.toml.lock"

if __name__ == "__main__":
    logging.basicConfig(level=get_log_level())

    if "GITHUB_PR_DIR" in os.environ:
        basedir = os.environ["GITHUB_PR_DIR"]
    else:
        basedir = os.environ["GITHUB_WORKSPACE"]
    GithubApi.submit_dependencies([(basedir, LOCKFILE)])
