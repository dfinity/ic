#!/usr/bin/env python3
"""
Fetch current membership of all code-owning teams in the dfinity org.

Writes teams.json: {"login_to_teams": {login: [team,...]}, "team_to_members": {team: [login,...]}}
Membership is the *current* membership (GitHub API has no historical team membership),
which is a known limitation when classifying older PRs.
"""

import json
import subprocess

# Teams referenced in .github/CODEOWNERS
TEAMS = [
    "core-protocol",
    "defi",
    "dre",
    "governance-team",
    "ic-owners-owners",
    "idx",
    "infrasec",
    "node",
    "product-security",
    "sdk",
]


def members_of(team):
    out = subprocess.check_output(
        ["gh", "api", "--paginate", f"orgs/dfinity/teams/{team}/members", "--jq", ".[].login"],
        text=True,
    )
    return [line for line in out.split() if line]


def main():
    login_to_teams = {}
    team_to_members = {}
    for t in TEAMS:
        members = members_of(t)
        team_to_members[t] = members
        for m in members:
            login_to_teams.setdefault(m, []).append(t)
    with open("teams.json", "w") as f:
        json.dump({"login_to_teams": login_to_teams, "team_to_members": team_to_members}, f, indent=2)
    print("team sizes:", {t: len(m) for t, m in team_to_members.items()})
    print("distinct members:", len(login_to_teams))


if __name__ == "__main__":
    main()
