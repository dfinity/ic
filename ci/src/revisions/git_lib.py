import subprocess
import pathlib
import logging
import argparse
import sys
from typing import Callable, List

class HelpfulParser(argparse.ArgumentParser):
    """An argparse parser that prints usage on any error."""

    def error(self, message):
        sys.stderr.write("error: %s\n" % message)
        self.print_help()
        sys.exit(2)

def init_helpful_parser() -> HelpfulParser:
    parser = HelpfulParser()
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    return parser

def get_logger(level) -> logging.Logger:
    FORMAT = "[%(asctime)s] %(levelname)-8s %(message)s"
    logging.basicConfig(format=FORMAT, level=level)
    return logging.getLogger("logger")

def get_repo_root() -> pathlib.Path:
    return pathlib.Path(subprocess.run(["git", "rev-parse", "--show-toplevel"], text=True, stdout=subprocess.PIPE).stdout.strip())

def sync_main_branch_and_checkout_branch(repo_root: pathlib.Path, main_branch: str, branch_to_checkout: str, logger: logging.Logger):
    if not repo_root.exists():
        raise Exception("Expected dir %s to exist", repo_root.name)

    subprocess.call(["git", "fetch", "origin", f"{main_branch}:{main_branch}"], cwd=repo_root)

    result = subprocess.run(["git", "status", "--porcelain"], stdout=subprocess.PIPE, text=True, check=True)
    if result.stdout.strip():
        logger.error("Found uncommited work! Commit and then proceed.")
        exit(2)

    if subprocess.call(["git", "checkout", branch_to_checkout], cwd=repo_root) == 0:
        # The branch already exists, update the existing MR
        logger.info("Found an already existing target branch")
    else:
        subprocess.check_call(["git", "checkout", "-b", branch_to_checkout], cwd=repo_root)
    subprocess.check_call(["git", "reset", "--hard", f"origin/{main_branch}"], cwd=repo_root)


def commit_and_create_pr(repo: str, repo_root: pathlib.Path, branch: str, check_for_updates_in_paths: List[str], logger: logging.Logger):
    git_modified_files = subprocess.check_output(["git", "ls-files", "--modified", "--others"], cwd=repo_root).decode(
        "utf8"
    )

    paths_to_add = [path for path in check_for_updates_in_paths if path in git_modified_files]

    if len(paths_to_add) > 0:
        logger.info("Creating/updating a MR that updates the saved NNS subnet revision")
        cmd = ["git", "add"] + paths_to_add
        logger.info("Running command '%s'", " ".join(cmd))
        logger.error("Would commit nice job!")
        exit(2)
        subprocess.check_call(cmd, cwd=repo_root)
        cmd = [
            "git",
            "-c",
            "user.name=CI Automation",
            "-c",
            "user.email=infra+github-automation@dfinity.org",
            "commit",
            "-m",
            "chore: Update Mainnet IC revisions file",
        ] + paths_to_add
        logger.info("Running command '%s'", " ".join(cmd))
        subprocess.check_call(
            cmd,
            cwd=repo_root,
        )
        subprocess.check_call(["git", "push", "origin", branch, "-f"], cwd=repo_root)

        if not subprocess.check_output(
            ["gh", "pr", "list", "--head", branch, "--repo", repo],
            cwd=repo_root,
        ).decode("utf8"):
            subprocess.check_call(
                [
                    "gh",
                    "pr",
                    "create",
                    "--head",
                    branch,
                    "--repo",
                    repo,
                    "--fill",
                ],
                cwd=repo_root,
            )
