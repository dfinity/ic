from collections import namedtuple
from io import StringIO

from codeowners_tools import main


def test_mismatches():
    github_teams = {
        "group1": ["user1", "user2", "user3"],
        "group2": ["user1"],
    }
    gitlab_teams = {
        "group1": ["user1", "user2", "user3"],
        "group2": ["user1", "user2"],
    }
    github_codeowners_file = StringIO(
        """\
/docs/          @user1 @user2
**/*.nix @dfinity-lab/group1
"""
    )
    gitlab_codeowners_file = StringIO(
        """\
/docs/          @user1 @user2
*.nix @dfinity-lab/teams/group1
/.dependencies @dfinity-lab/group2
"""
    )
    Blob = namedtuple("Blob", ["path"])
    Tree = namedtuple("Tree", ["blobs", "trees"])

    root = Tree(
        blobs=[Blob(path="file1"), Blob(path="shell.nix"), Blob(path=".dependencies")],
        trees=[
            Tree(blobs=[Blob(path="/docs/doc1")], trees=[]),
            Tree(blobs=[Blob(path="/rs/shell.nix"), Blob(path="/rs/code.rs")], trees=[]),
        ],
    )
    main.FLAGS(["./test_main.py"])  # initialize FLAGS
    mismatches = main.check_owners_mismatches(
        root, github_teams, gitlab_teams, github_codeowners_file, gitlab_codeowners_file
    )
    assert ".dependencies" in mismatches
