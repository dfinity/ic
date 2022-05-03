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

    python gen_gitlab_cargo_pipeline.py ../../rs/ --out=child-pipeline.yml
"""
import argparse
import io
import logging
import os.path
import pathlib
import random
import re
import traceback
import typing
from pprint import pformat

import git
import toml
import yaml

import git_changes
import gitlab_config.utils
import notify_slack


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


def generate_gitlab_yaml(
    crates,
    gitlab_ci_config,
    fout,
    force_pipeline=False,
    gitlab_ci_config_changes=False,
    prod_generic_test_job=None,
    disable_caching=False,
):
    """
    Generate a GitLab YAML pipeline that runs Cargo tests on the given crates.

    Args:
    ----
        crates: A set of strings of crate names to test.
        gitlab_ci_config: Parsed Yaml with the GitLab CI configuration.
        fout: Output file for the GitLab YAML file.
        force_pipeline: Generate a pipeline even if no crates have been changed.
        gitlab_ci_config_changes: Whether the gitlab ci configurations have been altered.
        prod_generic_test_job: Config for the generic prod test, if it should be added to the output.
        disable_caching: Whether the generated pipeline should disable capsule caching.

    """
    crate_test_name_overrides = gitlab_ci_config.get("crate_test_name_override") or {}
    logging.debug("Crate names override: %s", crate_test_name_overrides)

    crates_allowed_to_fail = set(gitlab_ci_config.get("crates_allowed_to_fail") or [])
    logging.debug("Crates allowed to fail: %s", crates_allowed_to_fail)

    crates_test_in_release = set(gitlab_ci_config.get("crates_tested_with_release_build") or [])
    logging.debug("Crates to test in release mode: %s", crates_test_in_release)

    crates_config_override = gitlab_ci_config.get("crates_config_override") or {}
    logging.debug("Crates with config override: %s", crates_config_override.keys())

    if crates or force_pipeline:
        if git_changes.is_protected():
            fout.write(
                """include:
  - local: /gitlab-ci/config/00--child-pipeline-root-protected.yml
"""
            )
        else:
            fout.write(
                """include:
  - local: /gitlab-ci/config/00--child-pipeline-root-unprotected.yml
"""
            )

        if "CI_PIPELINE_ID" in os.environ or gitlab_ci_config_changes:
            fout.write("variables:\n")

        if "CI_PIPELINE_ID" in os.environ:
            fout.write("  PARENT_PIPELINE_ID: %s\n" % (os.getenv("CI_PIPELINE_ID")))
            fout.write("  CDPRNET: cdpr0%s\n" % (random.randint(1, 5)))
            fout.write("  GIT_REVISION: $CI_COMMIT_SHA\n")
            if disable_caching:
                fout.write("  CAPSULE_EXTRA_ARGS: --placebo\n")

        if gitlab_ci_config_changes:
            fout.write("  GITLAB_CI_CONFIG_CHANGED: 'true'\n")

        for crate in sorted(crates):
            crate = crate_test_name_overrides.get(crate, crate)

            if crate in crates_config_override:
                crate_cfg = {crate: crates_config_override[crate]}
                fout.write("\n%s" % (yaml.dump(crate_cfg, indent=2)))
            else:
                fout.write("\n%s:\n" % (crate))
                fout.write("  extends: .cargo-crate-test\n")
                if crate in crates_test_in_release:
                    fout.write("  variables:\n")
                    fout.write('    CARGO_TEST_FLAGS_EXTRA: "--release"\n')
                if crate in crates_allowed_to_fail:
                    fout.write("  allow_failure: true\n")
        if prod_generic_test_job:
            fout.write(yaml.dump(prod_generic_test_job, indent=2))
    else:
        if prod_generic_test_job:
            fout.write(yaml.dump(prod_generic_test_job, indent=2))
        else:
            fout.write(
                """include:
  - local: /gitlab-ci/config/00--child-pipeline-noop-root.yml
"""
            )


def _generate_tests_may_raise_exception(
    rust_workspace: str,
    guestos_workspace: str,
    workspace_crates: set,
    gitlab_ci_config: dict,
    out: typing.TextIO,
    cargo_sample_size: int = 5,
):
    git_repo = git.Repo(rust_workspace, search_parent_directories=True)
    git_root = git_repo.git.rev_parse("--show-toplevel")
    prod_generic_test_job = get_prod_generic_test_job(git_root)

    """Generate a Gitlab YAML pipeline config (internal function). May raise exceptions."""
    if git_changes.is_protected():
        logging.info("on protected branch, test all crates")
        generate_gitlab_yaml(
            workspace_crates,
            gitlab_ci_config,
            out,
            prod_generic_test_job=prod_generic_test_job,
            disable_caching=True,
        )
        return

    disable_caching = (
        re.search(r"(\b)nocache(\b)", os.getenv("CI_MERGE_REQUEST_TITLE", "")) is not None
        or re.search(r"(\b)nocache(\b)", git_repo.commit().message) is not None
    )

    if os.environ.get("TRIGGER_PAYLOAD"):
        logging.info("Running a triggered pipeline, testing all crates")
        generate_gitlab_yaml(
            workspace_crates,
            gitlab_ci_config,
            out,
            prod_generic_test_job=prod_generic_test_job,
            disable_caching=disable_caching,
        )
        return

    if os.getenv("CI_MERGE_REQUEST_EVENT_TYPE", "") != "merge_train":
        if re.search(r"(\b)lessci(\b)", os.getenv("CI_MERGE_REQUEST_TITLE", "")):
            logging.debug("lessci detected in merge request title, running reduced set")
            generate_gitlab_yaml([], gitlab_ci_config, out, disable_caching=disable_caching)
            return
        if re.search(r"(\b)moreci(\b)", os.getenv("CI_MERGE_REQUEST_TITLE", "")):
            logging.debug("moreci detected in merge request title, running full set")
            generate_gitlab_yaml(
                workspace_crates,
                gitlab_ci_config,
                out,
                prod_generic_test_job=prod_generic_test_job,
                disable_caching=disable_caching,
            )
            return
    else:
        logging.info("On merge train pipeline use the parent pipeline's CI fast path")
        generate_gitlab_yaml([], gitlab_ci_config, out, disable_caching=disable_caching)
        return

    if re.search(r"(\b)moreci(\b)", git_repo.commit().message):
        logging.info("moreci in commit message, test all crates")
        generate_gitlab_yaml(
            workspace_crates,
            gitlab_ci_config,
            out,
            prod_generic_test_job=prod_generic_test_job,
            disable_caching=disable_caching,
        )
        return

    # Bypass entire cargo pipeline if
    #
    #   1. The word lessci appear in the commit message; OR
    #   2. The branch is not a release candidate AND the string "[hotfix]" appears in the commit message.
    #
    # Number 2 allows the release team to quickly merge hotfixes into rc branch, the cargo checks will be
    # performed in the new pipeline spawned after the commit is merged into the rc branch. With the Hybrid
    # GitHub/GitLab setup, GitLab cannot know into which branch a commit the PR will merge the change into.
    # Therefore, we use "[hotfix]" in the commit message to identify the change. After the GitLab migration,
    # we should remove the "[hotfix]" check, and just check the "CI_MERGE_REQUEST_TARGET_BRANCH_NAME".
    if re.search(r"(\b)lessci(\b)", git_repo.commit().message) or (
        re.search(r"\[hotfix\]", git_repo.commit().message)
        and not re.search(r"^rc--", os.environ.get("CI_COMMIT_REF_NAME"))
    ):
        # The commit message contained the word "lessci", which
        # instructed us to generate a noop pipeline.
        logging.info("lessci or [hotfix] in commit message, skip child pipeline")
        generate_gitlab_yaml([], gitlab_ci_config, out, disable_caching=disable_caching)
        return

    changed_files = git_changes.get_changed_files(git_root, [rust_workspace], ignored_files=["BUILD.bazel"])
    logging.debug("The following files have changed since the merge base: %s", changed_files)

    for file_name in changed_files:
        if file_name == f"{rust_workspace}/Cargo.toml":
            logging.info("CI config file %s changed, testing all crates", file_name)
            generate_gitlab_yaml(
                workspace_crates,
                gitlab_ci_config,
                out,
                prod_generic_test_job=prod_generic_test_job,
                disable_caching=disable_caching,
            )
            return

    # Filter out files that are either:
    #
    #   Strictly at root of the rust workspace, e.g. don't belong to a crate.
    #
    # Note: Unhandled minor edge case where rs/Cargo.toml changes to add a crate to the workspace,
    # but the PR does not add or change any files in the crate subdir.
    # https://gitlab.com/dfinity-lab/infra-group/infra/-/issues/321
    changed_files = [item for item in changed_files if os.path.dirname(item) != rust_workspace]

    logging.debug("The following files in the rust workspace have changed since the merge base:")
    logging.debug(pformat(sorted(changed_files), indent=4))

    changed_crates = files_to_crates(changed_files, rust_workspace)
    logging.debug("The following crates have direct changes since the merge base:")
    logging.debug(pformat(sorted(changed_crates), indent=4))

    marked_crate_to_dep = get_rdeps(rust_workspace, changed_crates)
    logging.debug("The following crates have direct and transitive changes since the merge base:")
    logging.debug(pformat(sorted(marked_crate_to_dep.keys()), indent=4))

    wmarked_crates_to_dep = {}
    for crate in marked_crate_to_dep:
        if crate in workspace_crates:
            wmarked_crates_to_dep[crate] = marked_crate_to_dep[crate]

    logging.debug(
        "The following crates belong to the rust workspace and have direct and transitive"
        " changes since the merge base"
    )

    log_rdeps(wmarked_crates_to_dep)

    cargo_test_sample_crates = set()
    if git_changes.nix_shell_changes(rust_workspace) or git_changes.ci_config_changes(git_root):
        logging.info("Nix or CI config changed, also test sample crates")

        # Exclude really expensive crates.
        fast_crates = sorted(list(workspace_crates - set("ic-nns-integration-tests")))
        random.Random(1).shuffle(fast_crates)
        cargo_test_sample_crates = set(fast_crates[:cargo_sample_size])

        generate_gitlab_yaml(
            cargo_test_sample_crates.union(set(wmarked_crates_to_dep.keys())),
            gitlab_ci_config,
            out,
            gitlab_ci_config_changes=True,
            prod_generic_test_job=prod_generic_test_job,
            disable_caching=disable_caching,
        )
    else:
        force_pipeline = git_changes.get_changed_files(git_root, [guestos_workspace]) or git_changes.get_changed_files(
            git_root, ["testnet", "ic-os", "scalability", "rs/workload_generator", "rs/registry/client"]
        )

        if not force_pipeline:
            prod_generic_test_job = None

        generate_gitlab_yaml(
            cargo_test_sample_crates.union(set(wmarked_crates_to_dep.keys())),
            gitlab_ci_config,
            out,
            force_pipeline,
            prod_generic_test_job=prod_generic_test_job,
            disable_caching=disable_caching,
        )


def get_prod_generic_test_job(git_root: str):
    gl_cfg = gitlab_config.DfinityGitLabConfig(git_root)
    gl_cfg_file = f"{git_root}/.gitlab-ci.yml"
    if os.path.exists(gl_cfg_file):
        gl_cfg.ci_cfg_load_from_file(open(gl_cfg_file))
        job_file = f"{git_root}/gitlab-ci/config/00--child-pipeline-prod-generic-test.yml"
        gl_cfg.ci_cfg_load_from_file(open(job_file))
        job = gl_cfg.ci_cfg["prod-generic-test"]
        job["stage"] = "prod-tests"
        result = {"prod-generic-test": job}
        return result


def generate_tests(
    rust_workspace: str,
    guestos_workspace: str,
    out: typing.TextIO,
    dry_run: bool = False,
    cargo_sample_size: int = 5,
):
    """
    Generate a Gitlab YAML pipeline config.

    We do this by computing all the crates directly or transitively affected between
    the git HEAD and the (HEAD, target_branch) mergebase, and outputs the result to a GitLab
    YAML pipeline config.

    When run on the master branch, the YAML config tests all crates in the workspace.
    In case of exceptions, an error message is posted to Slack and all crates are tested.

    Args:
    ----
        rust_workspace: A string path to the root of the cargo workspace.
        guestos_workspace: A string path to the guestos image build workspace.
        out: Output path of the GitLab YAML file.
        cargo_sample_size: Crate sample sizes for ci and nix file changes.
        dry_run: Don't post errors to Slack.

    """
    rust_workspace = os.path.abspath(rust_workspace)
    guestos_workspace = os.path.abspath(guestos_workspace)

    workspace_crates = _workspace_crates(rust_workspace)
    logging.debug("The following crates are in the workspace:")
    logging.debug(pformat(workspace_crates, indent=4))

    gitlab_ci_config = load_gitlab_ci_config(rust_workspace)

    # Fetch target branch before entering try-except, to prevent sending slack notifications
    # if a job gets cancelled while fetching the latest target branch.
    # This warms up the functools.lru_cache at get_merge_base.
    # E.g. Unnecessary slack notification was sent at
    # https://gitlab.com/dfinity-lab/core/dfinity/-/jobs/1023802832
    git_repo = git.Repo(rust_workspace, search_parent_directories=True)
    git_changes.get_merge_base(git_repo)

    try:
        _generate_tests_may_raise_exception(
            rust_workspace,
            guestos_workspace,
            workspace_crates,
            gitlab_ci_config,
            out,
            cargo_sample_size,
        )
    except Exception:  # pylint: disable=W0703
        logging.exception("Failed in crate_tests")
        if not dry_run:
            notify_slack.send_message(
                message=f"gen_gitlab_cargo_pipeline failed {os.environ.get('CI_JOB_URL')}\n{traceback.format_exc()}",
                channel="#precious-bots",
            )
        logging.info("crate dependency analysis failed, testing all crates")
        git_root = git_repo.git.rev_parse("--show-toplevel")
        prod_generic_test_job = get_prod_generic_test_job(git_root)
        generate_gitlab_yaml(
            workspace_crates,
            gitlab_ci_config,
            out,
            prod_generic_test_job=prod_generic_test_job,
            disable_caching=True,
        )

    logging.info("Wrote Cargo test GitLab pipeline to %s", out)


def generate_gitlab_yaml_for_noop(rust_workspace: str) -> str:
    """Return a string with the Gitlab YAML pipeline config for no-op builds."""
    rust_workspace = os.path.abspath(rust_workspace)

    gitlab_ci_config = load_gitlab_ci_config(rust_workspace)

    out = io.StringIO()
    generate_gitlab_yaml(set(), gitlab_ci_config, out)
    out.seek(0)
    return out.read()


def generate_gitlab_yaml_for_all_crates(rust_workspace: str) -> str:
    """Return a string with the Gitlab YAML pipeline config for all crates."""
    rust_workspace = os.path.abspath(rust_workspace)

    workspace_crates = _workspace_crates(rust_workspace)

    gitlab_ci_config = load_gitlab_ci_config(rust_workspace)

    out = io.StringIO()
    generate_gitlab_yaml(workspace_crates, gitlab_ci_config, out, disable_caching=True)
    out.seek(0)
    return out.read()


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

    generate_tests(
        rust_workspace=args.rust_workspace_path,
        guestos_workspace=args.guest_os_workspace_path,
        out=args.out,
    )
