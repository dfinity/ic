import csv
import re
from importlib import resources

from codeowners import CodeOwners as GithubParser


class Matcher(object):
    """
    Class representing both Github and Gitlab CODEOWNERS.

    It works for both Github and Gitlab. Github supports patterns like
    '**/*.nix' which don't work in Gitlab. However, we don't check
    patterns for correctness here, we assume they are correct. We only
    check that these correct pattenrs produce the same coverage.
    Since Gitlab patterns are simpler, they are also covered by
    the GitHub parser.

    """

    def __init__(self, inp, groups, user_map=dict()):
        """Create a codeowners object."""
        self.groups = groups
        self.user_map = user_map
        # Parse the codeowners file.
        self._owners = GithubParser(inp.read())

    def matches(self, path):
        """Return all CODEOWNERS terms matching the file."""
        return self._owners.matching_line(path)

    def owners(self, path):
        """Return all code owners for a given path in the repo."""
        result = set()
        owners, line_num = self.matches(path)
        for match_type, match_value in owners:
            match_value = re.sub(r"^@(dfinity-lab/)?(teams/)?", "", match_value)
            if match_type == "TEAM":
                for user in self.groups[match_value]:
                    result.add(self.user_map.get(user, user))
            else:
                result.add(self.user_map.get(match_value, match_value))
        return (result, line_num)


def parse_user_map():
    filename = resources.files("codeowners_tools").joinpath("user_map.csv")
    with resources.as_file(filename) as fname:
        with open(fname) as f:
            records = csv.reader(f)
            return {user_from: user_to for (user_from, user_to) in records}
