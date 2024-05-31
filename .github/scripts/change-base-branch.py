import os

from github import Github


def change_base_branch():
    pr_number = int(os.getenv('PR_NUMBER'))
    repo = os.getenv('GITHUB_REPOSITORY')
    token = os.getenv('GITHUB_TOKEN')
    desired_base = "mirroring"

    g = Github(token)
    repo = g.get_repo(repo)
    pull = repo.get_pull(pr_number)

    # Check if the base branch is already correct
    if pull.base.ref == desired_base:
        print(f"Base branch is already '{desired_base}'. No changes made.")
    else:
        pull.edit(base=desired_base)
        print(f"Base branch changed to '{desired_base}'.")

if __name__ == "__main__":
    change_base_branch()
