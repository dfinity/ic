import logging
import pathlib

import git  # type: ignore
from git import Repo


class GitRepo:
    """Generic wrapper around git repos. Allows us add logging and custom operations."""

    def __init__(self, repo_root=None):
        """Initialize an object at the provided repo_root."""
        base_path = pathlib.PurePath(__file__).parent.as_posix()
        self.repo = Repo(repo_root or base_path, search_parent_directories=True)
        if not repo_root:
            repo_root = self.repo.git.rev_parse("--show-toplevel")
        self._repo_root = repo_root

    def create_branch(self, branch_name, delete_existing=True):
        """Create a new branch with the provided name."""
        gitcmd = self.repo.git  # invoke git commands directly
        logging.info("%s: Creating a new branch {%s}", self.repo_path, branch_name)
        if delete_existing:
            try:
                gitcmd.branch("--list", branch_name)
                # The branch already exists, delete it
                gitcmd.branch("-D", branch_name)
            except git.GitCommandError:
                # The branch doesn't exist yet
                pass
        gitcmd.checkout("HEAD", b=branch_name)

    def add(self, path):
        """Stage path for commit."""
        gitcmd = self.repo.git  # invoke git commands directly
        logging.info("%s: Staging files from path %s", self.repo_path, path)
        gitcmd.add(path)

    def checkout(self, *kwargs):
        """Checkout with optional arguments."""
        gitcmd = self.repo.git  # invoke git commands directly
        logging.info("%s: git checkout %s", self.repo_path, " ".join(kwargs))
        gitcmd.checkout(*kwargs)

    def head_hash(self):
        """Get the revision at the HEAD."""
        gitcmd = self.repo.git  # invoke git commands directly
        return gitcmd.rev_parse("HEAD")

    def repo_root(self):
        """Get the repo root."""
        return self._repo_root

    def __str__(self):
        """Represent the GitRepo object as a string."""
        return f'Git repository at "{self.repo_path}"'
