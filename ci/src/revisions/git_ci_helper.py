import argparse
import logging
import pathlib
from enum import Enum

import git_lib


def get_logger(level) -> logging.Logger:
    FORMAT = "[%(asctime)s] %(levelname)-8s %(message)s"
    logging.basicConfig(format=FORMAT, level=level)
    return logging.getLogger("logger")


class Command(Enum):
    SYNC_AND_CHECKOUT = 1
    COMMIT_AND_CREATE_PR = 2


def main():
    parser = argparse.ArgumentParser(prog="GitCiHelper", description="Tool for automating git operations for CI")
    parser.add_argument(
        "--repo-root", help="Root of the repository", default=pathlib.Path("."), type=pathlib.Path, dest="repo_root"
    )
    parser.add_argument("--branch", help="Branch to checkout", type=str)

    subparsers = parser.add_subparsers(title="subcommands", description="valid commands", help="sub-command help")

    parser_sync_main_branch_and_checkout_branch = subparsers.add_parser(
        "sync-and-checkout", help="Sync with the main branch and checkout a different branch"
    )
    parser_sync_main_branch_and_checkout_branch.add_argument(
        "--main-branch", help="Main branch of the repository", type=str, default="master", dest="main_branch"
    )
    parser_sync_main_branch_and_checkout_branch.set_defaults(command=Command.SYNC_AND_CHECKOUT)

    parser_commit_and_create_pr = subparsers.add_parser(
        "commit-and-create-pr", help="Commit and create a pull request against the repository"
    )
    parser_commit_and_create_pr.add_argument(
        "--file", help="Check if the file is modified before commiting", type=str, action="append", dest="files"
    )
    parser_commit_and_create_pr.add_argument(
        "--repo", help="Github repository, `<owner>/<repo>`", type=str, default="dfinity/ic"
    )
    parser_commit_and_create_pr.add_argument("--message", "-m", help="Message to attach to the PR", type=str)
    parser_commit_and_create_pr.set_defaults(command=Command.COMMIT_AND_CREATE_PR)

    args = parser.parse_args()
    logger = get_logger(logging.DEBUG if args.verbose else logging.INFO)

    if hasattr(args, "command"):
        repo_root = args.repo_root
        branch = args.branch
        match args.command:
            case Command.SYNC_AND_CHECKOUT:
                main_branch = args.main_branch
                git_lib.sync_main_branch_and_checkout_branch(repo_root, main_branch, branch, logger)
                return
            case Command.COMMIT_AND_CREATE_PR:
                repo = args.repo
                files = args.files
                message = args.message
                git_lib.commit_and_create_pr(repo, repo_root, branch, files, logger, message)
                return

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
