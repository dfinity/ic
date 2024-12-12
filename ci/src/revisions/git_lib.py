import argparse
import logging
import pathlib
import subprocess
import sys
from typing import List


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
    return pathlib.Path(
        subprocess.run(["git", "rev-parse", "--show-toplevel"], text=True, stdout=subprocess.PIPE).stdout.strip()
    )


def sync_main_branch_and_checkout_branch(
    repo_root: pathlib.Path, main_branch: str, branch_to_checkout: str, logger: logging.Logger
):
    if not repo_root.exists():
        raise Exception("Expected dir %s to exist", repo_root.name)

    subprocess.call(["git", "fetch", "origin", f"{main_branch}:{main_branch}"], cwd=repo_root)

    result = subprocess.run(["git", "status", "--porcelain"], stdout=subprocess.PIPE, text=True, check=True)
    if result.stdout.strip():
        logger.warn("Uncommited work:\n%s", result.stdout.strip())
        logger.error("Found uncommited work! Commit and then proceed.")
        exit(2)

    if subprocess.call(["git", "checkout", branch_to_checkout], cwd=repo_root) == 0:
        # The branch already exists, update the existing MR
        logger.info("Found an already existing target branch")
    else:
        subprocess.check_call(["git", "checkout", "-b", branch_to_checkout], cwd=repo_root)
    subprocess.check_call(["git", "reset", "--hard", f"origin/{main_branch}"], cwd=repo_root)


def commit_and_create_pr(
    repo: str, repo_root: pathlib.Path, branch: str, check_for_updates_in_paths: List[str], logger: logging.Logger
):
    git_modified_files = subprocess.check_output(["git", "ls-files", "--modified", "--others"], cwd=repo_root).decode(
        "utf8"
    )

    paths_to_add = [path for path in check_for_updates_in_paths if path in git_modified_files]

    if len(paths_to_add) > 0:
        logger.info("Creating/updating a MR that updates the saved NNS subnet revision")
        cmd = ["git", "add"] + paths_to_add
        logger.info("Running command '%s'", " ".join(cmd))
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


def run_sync_main_branch_and_checkout_branch(args, logger):
    repo_root = args.repo_root
    branch = args.branch
    main_branch = args.main_branch
    sync_main_branch_and_checkout_branch(repo_root, main_branch, branch, logger)


def run_commit_and_create_pr(args, logger):
    repo = args.repo
    repo_root = args.repo_root
    branch = args.branch
    files = args.files
    commit_and_create_pr(repo, repo_root, branch, files, logger)


def main():
    parser = init_helpful_parser()
    parser.add_argument(
        "--repo-root", help="Root of the repository", default=pathlib.Path("."), type=pathlib.Path, dest="repo_root"
    )

    subparsers = parser.add_subparsers(title="subcommands", description="valid commands", help="sub-command help")

    parser_sync_main_branch_and_checkout_branch = subparsers.add_parser(
        "sync-and-checkout", help="Sync with the main branch and checkout a different branch"
    )
    parser_sync_main_branch_and_checkout_branch.add_argument(
        "--branch", help="Branch to checkout after syncing with main branch", type=str
    )
    parser_sync_main_branch_and_checkout_branch.add_argument(
        "--main-branch", help="Main branch of the repository", type=str, default="master", dest="main_branch"
    )
    parser_sync_main_branch_and_checkout_branch.set_defaults(func=run_sync_main_branch_and_checkout_branch)

    parser_commit_and_create_pr = subparsers.add_parser(
        "commit-and-create-pr", help="Commit and create a pull request against the repository"
    )
    parser_commit_and_create_pr.add_argument(
        "--branch", help="Branch to checkout after syncing with main branch", type=str
    )
    parser_commit_and_create_pr.add_argument(
        "--file", help="Check if the file is modified before commiting", type=str, action="append", dest="files"
    )
    parser_commit_and_create_pr.add_argument(
        "--repo", help="Github repository, `<owner>/<repo>`", type=str, default="dfinity/ic"
    )
    parser_commit_and_create_pr.set_defaults(func=run_commit_and_create_pr)

    args = parser.parse_args()
    logger = get_logger(logging.DEBUG if args.verbose else logging.INFO)

    if hasattr(args, "func"):
        args.func(args, logger)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
