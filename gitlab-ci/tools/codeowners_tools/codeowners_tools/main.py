"""Tools to compare Github and GitLab CODEOWNERS files to aid the migration."""
import itertools
import os.path
import shelve
from functools import wraps

from absl import app
from absl import flags
from codeowners_tools import codeowners_matcher
from git import Repo
from github import Github
from gitlab import Gitlab


FLAGS = flags.FLAGS

flags.DEFINE_bool("verbose", False, "Verbose output")
flags.DEFINE_bool("cached", False, "Use cached results to avoid API overload")
flags.DEFINE_integer("gitlab_team_group_id", 11764168, "Id of the Teams group in Gitlab")
flags.DEFINE_string("gitlab_uri", "https://gitlab.com", "URI of the Gitlab instance")
flags.DEFINE_string("org", "dfinity-lab", "Github organization name")
flags.DEFINE_string("repo_path", ".", "Repository checkout path")
flags.DEFINE_string("admin_users", "", "A comma separated string of admin users")
flags.DEFINE_bool("summary", False, "Show only a summary of the diffs")


# A tiny memoization func to avoid loading the API while debugging.
def memoize(func):
    @wraps(func)
    def wrapper(*args, **kwars):
        param = func.__name__
        with shelve.open(".cached.shelve") as d:
            if not FLAGS.cached or param not in d:
                d[param] = func(*args, **kwars)
            return d[param]

    return wrapper


@memoize
def read_github_teams():
    """Read Github teams data from the Github API."""
    g = Github(os.environ["GITHUB_ACCESS_TOKEN"])
    org = g.get_organization(FLAGS.org)
    teams = list(org.get_teams())
    team_graph = {}
    for team in teams:
        team_graph[team.name.lower()] = [member.login for member in team.get_members()]
    return team_graph


@memoize
def read_gitlab_teams():
    """Read gitlab teams data from the Gitlab API."""
    gl = Gitlab(FLAGS.gitlab_uri, private_token=os.environ["GITLAB_ACCESS_TOKEN"])
    teams_group = gl.groups.get(FLAGS.gitlab_team_group_id)
    team_graph = {}
    subgroups = teams_group.subgroups.list()
    for subgroup in subgroups:
        gr = gl.groups.get(subgroup.id)
        team_graph[gr.name.lower()] = [member.username for member in gr.members.list()]
    return team_graph


def walk_git_tree(repo_root_tree):
    def walk(root):
        for blob in root.blobs:
            yield blob.path
        for tree in root.trees:
            yield from walk(tree)

    yield from walk(repo_root_tree)


def list_diff(l1, l2):
    """Diff two lists of items, excluding special users, who perform the migration."""
    result = []
    for elem in l1:
        if elem not in l2:
            result.append("-" + elem)
    for elem in l2:
        if elem in FLAGS.admin_users.split(","):
            continue
        if elem not in l1:
            result.append("+" + elem)
    return result


def check_owners_mismatches(repo_root_tree, github_teams, gitlab_teams, github_codeowners_file, gitlab_codeowners_file):
    """Check mismatches between Github and Gitlab ownership for all repo paths."""
    mismatches = {}
    github_owners = codeowners_matcher.Matcher(
        github_codeowners_file, github_teams, codeowners_matcher.parse_user_map()
    )
    gitlab_owners = codeowners_matcher.Matcher(gitlab_codeowners_file, gitlab_teams)
    for path in walk_git_tree(repo_root_tree):
        codeowners_github, line_github = github_owners.owners(path)
        codeowners_gitlab, line_gitlab = gitlab_owners.owners(path)
        diff = list_diff(codeowners_github, codeowners_gitlab)
        if diff:
            mismatches[path] = (diff, line_github, line_gitlab)
    return mismatches


def group_mismatches(mismatches):
    groups = itertools.groupby(mismatches.items(), key=lambda item: item[1])
    return groups


def common_prefix(paths):
    i = 0
    while True:
        if len(paths[0]) <= i:
            return paths[0][:i]
        c = paths[0][i]
        j = 1
        while j < len(paths):
            if len(paths[j]) <= i or paths[j][i] != c:
                return paths[0][:i]
            j += 1
        i += 1


def find_mismatches(unused_argv):
    github_teams = read_github_teams()
    if FLAGS.verbose:
        print(github_teams)
    gitlab_teams = read_gitlab_teams()
    if FLAGS.verbose:
        print(gitlab_teams)

    repo = Repo(FLAGS.repo_path)
    with open(os.path.join(FLAGS.repo_path, ".github", "CODEOWNERS"), encoding="utf-8") as github_codeowners_file:
        with open(os.path.join(FLAGS.repo_path, ".gitlab", "CODEOWNERS"), encoding="utf-8") as gitlab_codeowners_file:
            mismatches = check_owners_mismatches(
                repo.head.ref.commit.tree, github_teams, gitlab_teams, github_codeowners_file, gitlab_codeowners_file
            )
            if FLAGS.summary:
                diffs = set(tuple(m[0]) for m in mismatches.values())
                for diff in diffs:
                    print(diff)
            else:
                groups = group_mismatches(mismatches)
                for group, mismatch in groups:
                    diff, line_github, line_gitlab = group
                    print(diff, line_github, line_gitlab, common_prefix([m[0] for m in mismatch]))


def main():
    app.run(find_mismatches)


if __name__ == "__main__":
    main()
