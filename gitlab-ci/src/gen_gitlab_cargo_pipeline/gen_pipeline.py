#!/usr/bin/env python3
"""
Produce a GitLab pipeline YAML config that run Cargo builds and tests.

Given a path to a rust workspace, computes all the crates directly or transitively affected between
the git HEAD and the (HEAD, target_branch) mergebase. The computation uses the Cargo.lock file to expand a
dependency graph, then determines which nodes [crates] have changed since the mergebase. Then
generates a GitLab pipeline YAML config that runs `cargo test -p` for all affected crates. And
runs `cargo build` and `cargo build --release` in the workspace root.

When run on the master branch, the YAML config always builds and tests all crates.

Typical example usage:

    python gen_pipeline.py ../../ --out=child-pipeline.yml
"""
import argparse
import logging
import os.path
import pathlib

import toml
import yaml


def locate_cargo_toml(fname, workspace_root):
    """
    Return the nearest Cargo.toml file.

    Searches recursively up the parent directories up to the root or
    workspace root.

    Args:
    ----
        fname: A string path to a file where to begin the search.
        workspace_root: A string path to the root of the cargo workspace.

    Returns
    -------
        A string with the path to a Cargo.toml file or empty if non-found.

    """
    cur_dir = pathlib.Path(fname).parent.as_posix()

    while True:
        parent_dir = os.path.dirname(cur_dir)
        # If the loop reaches the workspace root then one of the following conditions is true:
        #   1. The changed file's crate has been deleted
        #   2. The changed file does not belong to a crate.
        if cur_dir in (parent_dir, workspace_root):
            raise ValueError("Could not locate Cargo.toml for", fname)

        # The path might not exist if the git change was a deletion.
        if os.path.exists(cur_dir):
            file_list = os.listdir(cur_dir)
            if "Cargo.toml" in file_list:
                return os.path.join(cur_dir, "Cargo.toml")

        cur_dir = parent_dir


def files_to_crates(fnames, workspace_root):
    """
    Map a list of files to a set of crates they belong to.

    Args:
    ----
        fnames: A list or set of string filepaths.
        workspace_root: A string path to the root of the cargo workspace.

    Returns
    -------
        A set of strings corresponding to crate names.

    """
    ans = set()
    for fname in fnames:
        try:
            loc = locate_cargo_toml(fname, workspace_root)
        except ValueError as e:
            logging.debug("Could not locate Cargo.toml for file %s", fname, exc_info=e)
            continue

        parsed_toml = toml.load(loc)

        if "package" not in parsed_toml:
            raise ValueError("Could not parse package field in", loc)

        if "name" not in parsed_toml["package"]:
            raise ValueError("Could not parse package name field in", loc)

        ans.add(parsed_toml["package"]["name"])

    return ans


def load_gitlab_ci_config(workspace_root):
    """Return the parsed gitlab-ci-config.yml."""
    file_name = os.path.join(workspace_root, "gitlab-ci-config.yml")

    with open(file_name) as fin:
        yaml.add_multi_constructor("!reference", lambda loader, suffix, node: "", Loader=yaml.FullLoader)
        parsed_yml = yaml.load(fin, Loader=yaml.FullLoader)
        for field in [
            "crate_test_name_override",
            "crates_allowed_to_fail",
            "crates_tested_with_release_build",
        ]:
            if field not in parsed_yml:
                raise ValueError(f"Could not find '{field}' key in %s" % (file_name))
        return parsed_yml


def _workspace_crates(workspace_root):
    """
    Return the set of crates in the Rust workspace.

    Args:
    ----
        workspace_root: A string path to the root of the cargo workspace.

    Returns
    -------
        A set of strings corresponding to crate names.

    """
    parsed_toml = toml.load(os.path.join(workspace_root, "Cargo.toml"))

    if "workspace" not in parsed_toml:
        raise ValueError("Could not find workspace key in %s/Cargo.toml" % (workspace_root))
    if "members" not in parsed_toml["workspace"]:
        raise ValueError("Could not find workspace members key in %s/Cargo.toml" % (workspace_root))

    workspace_dirs = parsed_toml["workspace"]["members"]
    crates = set()
    for dir_name in workspace_dirs:
        crates.add(os.path.join(workspace_root, dir_name, "Cargo.toml"))

    return files_to_crates(crates, workspace_root)


def get_rdeps(workspace_root, crates):
    """
    Compute all crates with a direct or transitive dependency to a given set of crates.

    This algorithm first parses the direct dependency graph from the Cargo.lock file. It then marks
    the nodes [crates] that have been affected. At each iteration loop over every node n, if n is
    unmarked but has an an edge to a marked node, then mark n. The algorithm terminates when no new
    nodes have been marked.

    Args:
    ----
        workspace_root: A string path to the root of the cargo workspace.
        crates: A set of strings that correspond to crate names to search from.

    Returns
    -------
        A set of strings corresponding to crate names.

    """
    parsed_toml = toml.load(os.path.join(workspace_root, "Cargo.lock"))

    # marked_crate_to_dep maps marked crates to one dependency.
    marked_crate_to_dep = {}
    for crate in crates:
        marked_crate_to_dep[crate] = None

    new_marked_crates = True
    # The outer loop loops at most max(dist(c1, c2)) for all crates c1, c2 in the reverse
    # dependency graph, e.g. the max distance between any two crates. In practice, this should
    # be a single digit.
    while new_marked_crates:
        new_marked_crates = False
        for pkg in parsed_toml["package"]:
            crate = pkg["name"]

            # If this crate is already marked, then skip it.
            if crate in marked_crate_to_dep:
                continue

            for dep in pkg.get("dependencies", []):
                # Split a string that looks like:
                # "regex 1.3.9 (registry+https://github.com/rust-lang/crates.io-index)",
                split = dep.split()
                dep_crate = split[0]

                # ic-types:0.1.1 is a public crate so drop it.
                if dep_crate == "ic-types" and len(split) >= 2 and split[1] == "0.1.1":
                    continue

                # Does this crate directly depend on a crate we've marked?
                if dep_crate in marked_crate_to_dep:
                    marked_crate_to_dep[crate] = dep_crate
                    new_marked_crates = True
                    break

    return marked_crate_to_dep


def log_rdeps(marked_crate_to_dep):
    """
    Log the dependency chain of each transitively changed crate.

    Args:
    ----
        marked_crate_to_dep: A dictionary of strings that maps affected crates to a dependency.

    """
    try:
        out = "\n"
        for crate in sorted(marked_crate_to_dep.keys()):
            lst = []
            while crate:
                lst.append(crate)
                crate = marked_crate_to_dep.get(crate)
            out += "    " + ("-> ".join(lst)) + "\n"
        logging.debug(out)
    except KeyError:  # pylint: disable=W0703
        logging.error("Failed to log rdeps with marked_crate_to_dep: %s", marked_crate_to_dep)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("rust_workspace_path", help="path to the rust workspace")
    parser.add_argument("guest_os_workspace_path", help="path to the guest os workspace")
    parser.add_argument(
        "-o",
        "--out",
        help="where to store the generated cargo test yml (default is stdout)",
        type=argparse.FileType("w"),
        nargs="?",
        const="-",
        default="-",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
