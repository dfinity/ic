import subprocess
import pathlib
import logging

SAVED_VERSIONS_PATH = "mainnet-canisters.json"

def get_repo_root() -> str:
    return subprocess.run(["git", "rev-parse", "--show-toplevel"], text=True, stdout=subprocess.PIPE).stdout.strip()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    repo_root = pathlib.Path(get_repo_root())

    if not repo_root.exists():
        raise Exception("Expected dir %s to exist", repo_root.name)

    branch = "ic-nervous-system-wasms"
    repo = "dfinity/ic"

    # Sync only this branch, saves time in CI
    subprocess.call(["git", "fetch", "origin", "master:master"], cwd=repo_root)

    uncommited_work = subprocess.run(["git", "status", "--porcelain"], stdout=subprocess.PIPE, text=True, check=True)
    if uncommited_work.stdout.strip():
        raise Exception("Found uncommited work! Commit and then proceed.")

    if subprocess.call(["git", "checkout", branch], cwd=repo_root) == 0:
            # The branch already exists, update the existing MR
            logging.info("Found an already existing target branch")
    else:
        subprocess.check_call(["git", "checkout", "-b", branch], cwd=repo_root)
    subprocess.check_call(["git", "reset", "--hard", "origin/master"], cwd=repo_root)

    git_modified_files = subprocess.check_output(["git", "ls-files", "--modified", "--others"], cwd=repo_root).decode(
        "utf8"
    )

    if SAVED_VERSIONS_PATH in git_modified_files:
        logging.info("Creating/updating a MR that updates the saved NNS subnet revision")
        subprocess.check_call(["git", "add", SAVED_VERSIONS_PATH], cwd=repo_root)
        subprocess.check_call(
            [
                "git",
                "-c",
                "user.name=CI Automation",
                "-c",
                "user.email=infra+github-automation@dfinity.org",
                "commit",
                "-m",
                "chore: Update Mainnet IC revisions file",
                SAVED_VERSIONS_PATH,
            ],
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
    else:
        logging.info("No changes to be made!")
