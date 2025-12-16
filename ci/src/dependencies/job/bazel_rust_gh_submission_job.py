import logging

from integration.github.github_api import GithubApi
from model.log_level import get_log_level

if __name__ == "__main__":
    logging.basicConfig(level=get_log_level())

    GithubApi.submit_dependencies(["Cargo.Bazel.toml.lock"])
