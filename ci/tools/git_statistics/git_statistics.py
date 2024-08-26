import os
import re
import subprocess
from io import StringIO

import pandas as pd

pd.options.mode.chained_assignment = None

REPOSITORIES = [
    "nns-dapp",
    "internet-identity",
    "motoko",
    "sdk",
    "ic",
    "docs",
    "agent-js",
    "ic-staking-documentation",
    "keysmith",
    "examples",
]
COLUMNS = [
    "repository",
    "commits_2021",
    "commits_dec_2021",
    "u_devs_2021",
    "u_devs_dec",
    "u_devs_over_10_commits_dec",
    "u_devs_over_100_lines_dec",
]
BEG_YEAR = 1609459200
END_YEAR = 1640995199
BEG_DEC = 1638316800


def clone_repositories(repositories):
    print("--- CLONING REPOSITORIES ---")

    # Create /repositories if doesn't exist
    try:
        os.mkdir("repositories")
    except OSError:
        pass

    for repository in repositories:
        subprocess.run(["git", "clone", f"git@github.com:dfinity/{repository}.git"], cwd="repositories/")
    print("")


def get_commit_history(repository):
    path = "raw_history.txt"

    raw_history = open(path, "w")
    subprocess.run(
        ["git", "--no-pager", "log", "--shortstat", "--pretty=format:%ae,%ct"],
        cwd=f"repositories/{repository}/",
        stdout=raw_history,
    )
    raw_history.close()

    raw_history = open(path, "r").read()
    git_log = re.sub(
        r"(^.+,\d+)\n [0-9]* file(s)? changed(, ([0-9]*) insertion(s)?\(\+\))?(, ([0-9]*) deletion(s)?\(-\))?\n$",
        r"\g<1>,\g<4>,\g<7>",
        raw_history,
        flags=re.MULTILINE,
    )

    os.remove(path)

    csv = StringIO("email,timestamp,additions,deletions\n" + git_log)
    return pd.read_csv(csv)


def get_commits_in_range(df, since, until):
    return df.loc[(df["timestamp"] > since) & (df["timestamp"] < until)]


def get_u_devs(df):
    return df.groupby("email").size().reset_index(name="counts")


def get_u_devs_commit_threshold(u_devs, commit_threshold):
    df = u_devs
    return df.loc[df["counts"] >= commit_threshold]


def get_u_devs_lines_threshold(df, lines_threshold):
    df["lines"] = df["additions"] + df["deletions"]
    df = df.groupby("email").agg({"lines": "sum"}).reset_index()
    return df.loc[df["lines"] >= lines_threshold]


def get_emails(df):
    if "email" in df.columns:
        return df["email"].tolist()

    return []


def unique_total(df, column):
    devs = df[column].tolist()
    # Remove none items
    devs = [item for item in devs if item]
    # Flatten list
    devs = [item for sublist in devs for item in sublist]

    return len(set(devs))


clone_repositories(REPOSITORIES)

raw_data = []

print("--- RETRIEVING COMMIT HISTORY ---")
for repository in REPOSITORIES:
    df = get_commit_history(repository)
    df_2021 = get_commits_in_range(df, BEG_YEAR, END_YEAR)
    df_dec = get_commits_in_range(df, BEG_DEC, END_YEAR)

    commits_2021 = len(df_2021.index)
    commits_dec = len(df_dec.index)
    # u for unique
    u_devs_2021 = get_u_devs(df_2021)
    u_devs_dec = get_u_devs(df_dec)
    u_devs_over_10_commits_dec = get_emails(get_u_devs_commit_threshold(u_devs_dec, 10))
    u_devs_over_100_lines_dec = get_emails(get_u_devs_lines_threshold(df_dec, 100))

    raw_data.append(
        [
            repository,
            commits_2021,
            commits_dec,
            get_emails(u_devs_2021),
            get_emails(u_devs_dec),
            u_devs_over_10_commits_dec,
            u_devs_over_100_lines_dec,
        ]
    )

print("--- COMPUTING TOTALS ---")
raw_data.append(["total"])
df = pd.DataFrame(raw_data, columns=COLUMNS)

df.at[10, "commits_2021"] = df["commits_2021"].sum()
df.at[10, "commits_dec_2021"] = df["commits_dec_2021"].sum()
# Computing unions
for column in COLUMNS[3:]:
    df.at[10, column] = unique_total(df, column)
    df[column] = df[column].apply(lambda x: x if type(x) is int else len(set(x)))

print(df)
print("--- SAVING CSV ---")
df.to_csv("output.csv", index=False)
print("Done: output.csv")
