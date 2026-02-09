import logging
import os

from integration.github.github_api import GithubApi
from model.log_level import get_log_level

LOCKFILE = "Cargo.Bazel.toml.lock"

if __name__ == "__main__":
    logging.basicConfig(level=get_log_level())

    if "ACTIONS_ID_TOKEN_REQUEST_URL" in os.environ:
        logging.error("ACTIONS_ID_TOKEN_REQUEST_URL set")
    else:
        logging.error("ACTIONS_ID_TOKEN_REQUEST_URL not set")
    if "ACTIONS_ID_TOKEN_REQUEST_TOKEN" in os.environ:
        logging.error("ACTIONS_ID_TOKEN_REQUEST_TOKEN set")
    else:
        logging.error("ACTIONS_ID_TOKEN_REQUEST_TOKEN not set")
